package certhelper

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"log"
	"log/slog"
	"net"
	"net/url"
	"os"
	"time"
)

type CertificateType string

const (
	TypeServerCertificate       CertificateType = "server"
	TypeClientCertificate       CertificateType = "client"
	TypeCACertificate           CertificateType = "ca"
	TypeIntermediateCertificate CertificateType = "intermediate"
)

var targetFileMap = map[CertificateType]string{
	TypeCACertificate:           "ca.pem",
	TypeIntermediateCertificate: "intermediate.pem",
	TypeServerCertificate:       "server.pem",
	TypeClientCertificate:       "client.pem",
}

var expireIn = 3 * time.Minute

var authDomain string

func SetDomain(domain string) {
	if authDomain != "" {
		panic("auth domain already set")
	}
	authDomain = domain
}

func GenCert(name string, parent *x509.Certificate, certType CertificateType, certificatePublicKey crypto.PublicKey, signingKey crypto.Signer, dnsNames ...string) (derBytes []byte, err error) {
	defer TimeFunction("GenCert")()

	logger := slog.With("name", name, "type", certType)
	if certificatePublicKey == nil || signingKey == nil {
		logger.Error("Key is nil")
		return nil, errors.New("nil key")
	}

	if authDomain == "" {
		return nil, errors.New("authdomain not set")
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(10 * 365 * 24 * time.Hour)
	keyUsage := x509.KeyUsageDigitalSignature

	eku := []x509.ExtKeyUsage{}

	var isCA bool
	switch certType {
	case TypeCACertificate:
		logger.Debug("creating CA cert")
		isCA = true
		keyUsage |= x509.KeyUsageCertSign | x509.KeyUsageCRLSign
		// parent = &template
	case TypeIntermediateCertificate:
		logger.Debug("creating Intermediate cert")
		isCA = true
		keyUsage |= x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	case TypeServerCertificate:
		logger.Debug("creating server cert", "expiresIn", expireIn)
		keyUsage |= x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature
		eku = append(eku, x509.ExtKeyUsageServerAuth)
		notAfter = notBefore.Add(expireIn)
	case TypeClientCertificate:
		logger.Debug("creating client cert", "expiresIn", expireIn)
		keyUsage |= x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature
		eku = append(eku, x509.ExtKeyUsageClientAuth)
		notAfter = notBefore.Add(expireIn)
	default:
		return nil, errors.New("invalid certificate type")
	}

	finalDNSNames := []string{"localhost"}
	for _, name := range dnsNames {
		if len(name) > 0 {
			finalDNSNames = append(finalDNSNames, name)
		}
	}

	template := x509.Certificate{
		IsCA: isCA,
		Subject: pkix.Name{
			CommonName: name,
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage:              keyUsage,
		ExtKeyUsage:           eku,
		BasicConstraintsValid: true,
		DNSNames:              finalDNSNames,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		URIs: []*url.URL{{
			Scheme: "spiffe",
			Host:   authDomain,
			Path:   name,
		}},
	}

	logger.Info("creating cert with uri", "uri", template.URIs[0].String())
	if parent == nil {
		parent = &template
	}
	derBytes, err = x509.CreateCertificate(rand.Reader, &template, parent, certificatePublicKey, signingKey)
	if err != nil {
		return
	}

	return
}

func WriteCertToFile(targetFile string, derBytes []byte) error {
	logger := slog.Default()
	logger.Info("writing cert to file", "file", targetFile)
	f, err := os.OpenFile(targetFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = f.Write(DERToPEM("CERTIFICATE", derBytes))
	if err != nil {
		return err
	}

	return nil
}

// This returns System Cert Pool added with the CA certificates read from local files
func GetCertPool() *x509.CertPool {
	TimeFunction("GetCertPool")
	cp, err := x509.SystemCertPool()
	if err != nil {
		log.Fatalf("failed to get system certpool: %s", err)
	}

	if caCert, err := os.ReadFile(targetFileMap[TypeCACertificate]); err == nil {
		if cp.AppendCertsFromPEM(caCert) {
			slog.Default().Debug("added our own root CA to cert pool")
		}
	}
	if intermediateCert, err := os.ReadFile(targetFileMap[TypeIntermediateCertificate]); err == nil {
		if cp.AppendCertsFromPEM(intermediateCert) {
			slog.Default().Debug("added our own intermediate CA to cert pool")
		}
	}
	return cp
}
