package certs

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"log"
	"log/slog"
	"net"
	"net/url"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

var (
	caCert     *x509.Certificate
	srvCert    *x509.Certificate
	clientCert *x509.Certificate
	caPool     *x509.CertPool

	privKey      *ecdsa.PrivateKey
	privKeyBytes []byte

	redisClient *redis.Client
)

var tlsLock sync.Mutex

type CertConfig struct {
	TrustDomain   string
	CACertificate *x509.Certificate
}

func CertInit(cfg *CertConfig) {
	tlsLock.Lock()
	defer tlsLock.Unlock()

	start := time.Now()
	log.Println("Creating new certificates...")
	genPrivKey()
	genCA(cfg)
	cfg.CACertificate = caCert

	genServerCert(cfg)
	genClientCert(cfg)

	log.Printf("all certificates and keys created in %s", time.Since(start))
}

func genClientCert(cfg *CertConfig) {
	var err error
	name := "cert-client"

	bb := genCert(name, typeClientCertificate, cfg)
	clientCert, err = x509.ParseCertificate(bb)
	if err != nil {
		slog.Error("failure to parse ca cert", "error", err)
		return
	}
}

func genServerCert(cfg *CertConfig) {
	var err error
	name := "cert-server"

	bb := genCert(name, typeServerCertificate, cfg)
	srvCert, err = x509.ParseCertificate(bb)
	if err != nil {
		slog.Error("failure to parse ca cert", "error", err)
		return
	}

}

func genCA(cfg *CertConfig) {
	var err error
	name := "cert-ca"

	bb := genCert(name, typeCACertificate, cfg)
	caCert, err = x509.ParseCertificate(bb)
	if err != nil {
		slog.Error("failure to parse ca cert", "error", err)
		return
	}
}

// Get new certificate
func GetCertificate() (*tls.Certificate, error) {
	cert, key := DERToPEM(srvCert.Raw, privKeyBytes)
	ret, err := tls.X509KeyPair(cert, key)
	return &ret, err
}

func GetCACertificate() *x509.Certificate {
	return caCert
}

func DERToPEM(derCert, derKey []byte) (pemCert, pemKey []byte) {
	certBlock := pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derCert,
	}
	keyBlock := pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: derKey,
	}
	return pem.EncodeToMemory(&certBlock), pem.EncodeToMemory(&keyBlock)
}

func X509ClientCert() *x509.Certificate {
	tlsLock.Lock()
	defer tlsLock.Unlock()

	return clientCert
}

func GetPool(cfg *CertConfig) *x509.CertPool {
	tlsLock.Lock()
	defer tlsLock.Unlock()

	log.Printf("GetPool called")
	if caPool == nil {
		log.Printf("building the pool, adding %d as root ca...", cfg.CACertificate.SerialNumber)
		caPool = x509.NewCertPool()
		caPool.AddCert(cfg.CACertificate)
		PrintCert(context.Background(), cfg.CACertificate)
	}

	return caPool
}

// func GetClientPool() *x509.CertPool {
// 	tlsLock.Lock()
// 	defer tlsLock.Unlock()

// 	p := x509.NewCertPool()
// 	p.AddCert(clientCert)
// 	return p
// }

func CertHash(x *x509.Certificate) string {
	hash := sha256.New()
	hash.Write(x.Raw)
	return hex.EncodeToString(hash.Sum(nil))
}

func PrintCert(ctx context.Context, x *x509.Certificate) {
	sumHex := CertHash(x)
	// sumBase64 := base64.RawURLEncoding.EncodeToString(sum)
	// sumHex := hex.EncodeToString(sum)

	h := sha1.New()
	h.Write(x.RawSubjectPublicKeyInfo)
	skid := h.Sum(nil)

	h.Reset()
	h.Write(x.RawIssuer)
	akid2 := h.Sum(nil)

	slog.InfoContext(ctx, "certificate info",
		"subject", x.Subject,
		"issuer", x.Issuer,
		"isCA", x.IsCA,
		"expires", x.NotAfter.Format(time.DateTime),
		"serial", x.SerialNumber,
		"sha256sum", sumHex,
		"akid", hex.EncodeToString(x.AuthorityKeyId),
		"akid2", hex.EncodeToString(akid2),
		"skid", hex.EncodeToString(skid),
	)
	// slog.InfoContext(ctx, "certificate", "subject", x.Subject, "issuer", x.Issuer, "serial", x.SerialNumber, "hexSum", sumHex)
}

func genPrivKey() {
	var pkBytes []byte

	slog.Info("generating new private key")
	newPrivKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalln(err)
	}

	pkBytes, err = x509.MarshalPKCS8PrivateKey(newPrivKey)
	if err != nil {
		log.Fatalln(err)
	}

	privKeyBytes = pkBytes
}

func GetPrivateKey() *ecdsa.PrivateKey {
	key, err := x509.ParsePKCS8PrivateKey(privKeyBytes)
	if err != nil {
		log.Fatalln(err)
	}

	return key.(*ecdsa.PrivateKey)
}

type certificateType string

const (
	typeServerCertificate certificateType = "server"
	typeClientCertificate certificateType = "client"
	typeCACertificate     certificateType = "ca"
)

func genCert(name string, certType certificateType, cfg *CertConfig) []byte {
	var err error

	slog.Info("generating new cert", "name", name, "type", certType, "trustDomain", cfg.TrustDomain)

	parent := cfg.CACertificate

	// serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	// serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	// if err != nil {
	// 	log.Fatalf("Failed to generate serial number: %v", err)
	// }

	notBefore := time.Now()
	// notAfter := notBefore.Add(10 * 365 * 24 * time.Hour)
	notAfter := notBefore.Add(10 * 365 * 24 * time.Hour)
	keyUsage := x509.KeyUsageDigitalSignature

	var eku []x509.ExtKeyUsage
	if certType == typeCACertificate {
		eku = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	} else {
		eku = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	}
	// switch certType {
	// case typeServerCertificate:
	// 	eku = append(eku, x509.ExtKeyUsageServerAuth)
	// case typeClientCertificate:
	// 	eku = append(eku, x509.ExtKeyUsageClientAuth)
	// default:
	// }

	td, err := url.Parse(cfg.TrustDomain)
	if err != nil {
		log.Fatalf("failure to parse %s: %s", cfg.TrustDomain, err)
	}

	log.Printf("parsed trustdomain: %s", td.String())
	template := x509.Certificate{
		// SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: name,
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage:              keyUsage,
		ExtKeyUsage:           eku,
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		URIs:                  []*url.URL{td},
	}

	if certType == typeCACertificate {
		slog.Debug("creating CA cert")
		template.IsCA = true
		template.KeyUsage |= x509.KeyUsageCertSign
		parent = &template
	} else {
		slog.Debug("creating normal cert", "name", name, "type", certType)
		if parent == nil {
			parent = &template
		}
	}

	privKey := GetPrivateKey()

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, parent, privKey.Public(), privKey)
	if err != nil {
		log.Fatalf("Failed to create certificate: %v", err)
	}

	slog.Debug(fmt.Sprintf("certificate %s created", name), "expiresIn", time.Until(notAfter))
	return derBytes
}
