package mtlscfg

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"sync/atomic"
	"time"

	"github.com/saltsa/tlsauthlib/certhelper"
	"go.uber.org/zap"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"

	pb "github.com/saltsa/tlsauthlib/proto"
)

const reconnectInterval = 10 * time.Second

var (
	ErrNoTLSConnection     = errors.New("no tls connection found")
	ErrNoTLSCert           = errors.New("no peer certificate found")
	ErrInvalidNumberOfURIs = errors.New("there must be exactly one uri in certificate")
	ErrInvalidURIScheme    = errors.New("URI scheme invalid")
	ErrInvalidHost         = errors.New("host in URI was invalid")
	ErrInvalidPath         = errors.New("path in URI was empty")
)

type MTLSConfigurator struct {
	tlsCert atomic.Pointer[tls.Certificate]
	cp      atomic.Pointer[x509.CertPool]

	coordinationServer string
	certType           certhelper.CertificateType

	localIdentity  string
	remoteIdentity string

	privateKey crypto.Signer

	cpReady       chan bool
	certAvailable chan bool

	certClient pb.CertProviderClient
}

func NewClientConfig(ctx context.Context, certServer string, options ...Option) (*MTLSConfigurator, error) {
	return newMtlsClient(ctx, certServer, certhelper.TypeClientCertificate, options...)
}

func NewServerConfig(ctx context.Context, certServer string, options ...Option) (*MTLSConfigurator, error) {
	return newMtlsClient(ctx, certServer, certhelper.TypeServerCertificate, options...)
}

func Must(mc *MTLSConfigurator, err error) *MTLSConfigurator {
	if err != nil {
		panic(err)
	}
	return mc
}

func newMtlsClient(ctx context.Context, srv string, ct certhelper.CertificateType, options ...Option) (*MTLSConfigurator, error) {
	ret := &MTLSConfigurator{
		cpReady:            make(chan bool, 1),
		certAvailable:      make(chan bool, 1),
		coordinationServer: srv,
		certType:           ct,
	}

	for _, o := range options {
		o(ret)
	}

	err := ret.grpcClient(ctx)
	if err != nil {
		return nil, err
	}
	return ret, nil
}

func (mc *MTLSConfigurator) GetTLSConfig() *tls.Config {
	pool := mc.cp.Load()
	tcfg := &tls.Config{
		// common
		MinVersion: tls.VersionTLS13,
		VerifyConnection: func(cs tls.ConnectionState) error {
			return verifyCertificateIdentity(cs.PeerCertificates, mc.coordinationServer, mc.remoteIdentity)
		},

		// used only by servers
		ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs:  pool,
		GetConfigForClient: func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
			zap.S().Debugf("GetConfigForClient for servername %s, not implemented. Returning nil (no error)", chi.ServerName)
			return nil, nil
		},
		GetCertificate: func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if p := mc.tlsCert.Load(); p != nil {
				return p, nil
			}
			return nil, errors.New("no server certificate available")
		},

		// used only by clients
		RootCAs:    pool,
		ServerName: "localhost", // localhost is added to certs by default and we use it, so cert validation will succeed
		GetClientCertificate: func(cri *tls.CertificateRequestInfo) (*tls.Certificate, error) {
			if p := mc.tlsCert.Load(); p != nil {
				return p, nil
			}
			return nil, errors.New("no client certificate available")
		},
	}
	return tcfg
}

func (mc *MTLSConfigurator) GetGRPCTransportCredentials() credentials.TransportCredentials {
	return credentials.NewTLS(mc.GetTLSConfig())
}

func (mc *MTLSConfigurator) grpcClient(ctx context.Context) error {
	log := zap.S()

	log.Debugf("receiving certs from server %s", mc.coordinationServer)
	mc.privateKey = certhelper.MustGetPrivKey("client.key")
	csr, err := certhelper.GenCSR(mc.privateKey)
	if err != nil {
		return err
	}

	log.Debugf("initialize GRPC client")
	creds := credentials.NewTLS(&tls.Config{
		MinVersion: tls.VersionTLS13,
		RootCAs:    certhelper.GetCertPool(),
	})
	conn, err := grpc.NewClient(mc.coordinationServer, grpc.WithTransportCredentials(creds))
	if err != nil {
		return err
	}
	mc.certClient = pb.NewCertProviderClient(conn)

	log.Info("starting background processes and waiting root certificate received")
	go mc.certificateUpdater(ctx, csr)
	go mc.rootCAUpdater(ctx)

	select {
	case <-ctx.Done():
		return errors.New("context was done")
	case <-mc.cpReady:
		log.Info("root certificate pool ready")
	}
	return nil
}

func (mc *MTLSConfigurator) updateCertificate(data [][]byte) {
	log := zap.S()

	if len(data) == 0 {
		log.Error("server sent zero length data, cannot update cert")
		return
	}

	c, err := x509.ParseCertificate(data[0])
	if err != nil {
		log.Errorf("failure to parse cert: %s", err)
		return
	}

	err = verifyCertificateIdentity([]*x509.Certificate{c}, mc.coordinationServer, mc.localIdentity)
	if err != nil {
		log.Errorf("failed to get verify certificate role: %s", err)
		return
	}

	p := mc.tlsCert.Load()
	if p != nil && c.Equal(p.Leaf) {
		log.Debug("server sent our current cert. No update needed.")
		return
	}
	newCert := &tls.Certificate{
		Certificate: data,
		PrivateKey:  mc.privateKey,
		Leaf:        c,
	}
	mc.tlsCert.Store(newCert)
}

func (mc *MTLSConfigurator) certificateUpdater(ctx context.Context, csr []byte) {
	log := zap.S()
	t := time.NewTicker(reconnectInterval)
	for {
		if err := ctx.Err(); err != nil {
			log.Infof("FetchCertificate is now done: %s", err)
			return
		}

		signCertificateRequest := &pb.SignCertificate{
			Csr:  csr,
			Type: string(mc.certType),
		}

		fcResp, err := mc.certClient.FetchCertificate(ctx, signCertificateRequest)
		if err != nil {
			log.Error("failed to open fetch certificate stream", "err", err)
			<-t.C
			continue
		}
		log.Debug("receiving certificates")
		for {
			resp, err := fcResp.Recv()
			if err != nil {
				grpcStatus := status.Code(err)
				if grpcStatus != codes.OK {
					log.With("grpcStatus", grpcStatus).Errorf("stream receive failure: %s", err)
				}
				<-t.C
				break
			}
			mc.updateCertificate(resp.GetCertificate())

			select {
			case <-ctx.Done():
				return
			case mc.certAvailable <- true:
				log.Info("certificate is now available for use")
			default:
			}
		}
	}
}

func (mc *MTLSConfigurator) rootCAUpdater(ctx context.Context) {
	log := zap.S()
	t := time.NewTicker(reconnectInterval)

	for {
		if err := ctx.Err(); err != nil {
			log.Info("FetchRootCerts is now done, context closed", "err", err)
			return
		}
		log.Debug("fetching root certs")
		stream, err := mc.certClient.FetchRootCerts(ctx, &pb.GetRootCertsRequest{})
		if err != nil {
			log.Error("root cert fetch", "err", err)
			<-t.C
			continue
		}

		log.Debug("root certs stream open")
		for {
			resp, err := stream.Recv()
			if err != nil {
				log.Error("root bundle stream receive failed", "err", err)
				<-t.C
				break
			}

			if bundles := resp.GetBundles(); bundles != nil {
				newPool := x509.NewCertPool()
				oldCp := mc.cp.Load()
				for key, val := range bundles {
					cert, err := x509.ParseCertificate(val)
					if err != nil {
						log.Error("failure to add bundle", "err", err)
						continue
					}
					log.Debugf("add %s to bundle, it's subject %s and serial %d", key, cert.Subject.String(), cert.SerialNumber)
					newPool.AddCert(cert)
				}

				updated := !oldCp.Equal(newPool)
				if updated {
					log.Info("new set of root certificates. Updating pool.")
					mc.cp.Store(newPool)
				} else {
					log.Debug("cert pool not updated")
				}
				select {
				case mc.cpReady <- true:
				default:
				}
			}
		}
	}
}
