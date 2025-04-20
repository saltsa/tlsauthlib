package tlsauthlib

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"net"
	"slices"
	"time"

	"github.com/saltsa/tlsauthlib/internal/certs"
	"github.com/saltsa/tlsauthlib/util"
)

type contextKey struct {
	name string
}

func (k *contextKey) String() string { return "tlsauthlib context value " + k.name }

var SerialContextKey = &contextKey{"tls-client-serial"}

func GetServerTLSConfig(cfg *util.Config) *tls.Config {
	tlsConfig := &tls.Config{
		GetCertificate: cfg.GetServerCertificate,
		MinVersion:     tls.VersionTLS13,
		ClientAuth:     tls.RequireAnyClientCert,

		VerifyConnection: func(cs tls.ConnectionState) error {
			allowedCerts := cfg.GetAllowedCerts()
			if len(cs.PeerCertificates) == 0 {
				return errors.New("no peer certificate available")
			}

			log.Printf("got %d peer certificates, %d verified chains and %d SCTs", len(cs.PeerCertificates), len(cs.VerifiedChains), len(cs.SignedCertificateTimestamps))
			xCert := cs.PeerCertificates[0]
			receivedCertHash := certs.CertHash(xCert)

			valid := slices.Contains(allowedCerts, receivedCertHash)

			if !valid {
				slog.Debug("cert not allowed", "allowedCertCount", len(allowedCerts))
				if len(allowedCerts) == 0 {
					cfg.ConfigAddCert(receivedCertHash)
				}
				return fmt.Errorf("cert '%s' not found from allowed certs", receivedCertHash)
			}
			return validateClientCertificate(xCert)
		},
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			log.Printf("call to verify peer certificate, verifiedChains len %d", len(verifiedChains))
			return nil
		},
	}

	return tlsConfig
}

func GetClientTLSConfig(cfg *util.Config) *tls.Config {
	return &tls.Config{
		MinVersion:           tls.VersionTLS13,
		InsecureSkipVerify:   true,
		GetClientCertificate: cfg.GetClientCertificate,
	}
}

func ConnStateContext(ctx context.Context, c net.Conn) context.Context {
	nc, ok := c.(*tls.Conn)
	if !ok {
		return ctx
	}

	err := nc.Handshake()
	if err != nil {
		return ctx
	}

	tlsCS := nc.ConnectionState()
	if len(tlsCS.PeerCertificates) == 0 {
		return ctx
	}
	cert := tlsCS.PeerCertificates[0]

	newCtx := context.WithValue(ctx, SerialContextKey, cert.SerialNumber.String())
	return newCtx
}

func validateClientCertificate(c *x509.Certificate) error {
	now := time.Now()
	if now.Before(c.NotBefore) {
		return x509.CertificateInvalidError{
			Cert:   c,
			Reason: x509.Expired,
			Detail: fmt.Sprintf("current time %s is before %s", now.Format(time.RFC3339), c.NotBefore.Format(time.RFC3339)),
		}
	} else if now.After(c.NotAfter) {
		return x509.CertificateInvalidError{
			Cert:   c,
			Reason: x509.Expired,
			Detail: fmt.Sprintf("current time %s is after %s", now.Format(time.RFC3339), c.NotAfter.Format(time.RFC3339)),
		}
	}
	if c.KeyUsage|x509.KeyUsageDigitalSignature == 0 {
		return x509.CertificateInvalidError{
			Cert:   c,
			Reason: x509.IncompatibleUsage,
			Detail: "must have DigitalSignature keyusage",
		}
	}

	if !slices.Contains(c.ExtKeyUsage, x509.ExtKeyUsageClientAuth) {
		return x509.CertificateInvalidError{
			Cert:   c,
			Reason: x509.IncompatibleUsage,
			Detail: "must have client auth key usage",
		}
	}
	return nil
}
