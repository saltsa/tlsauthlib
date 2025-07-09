package tlsauthlib

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"slices"
	"time"

	"github.com/saltsa/tlsauthlib/internal/certs"
)

type contextKey struct {
	name string
}

func (k *contextKey) String() string { return "tlsauthlib context value " + k.name }

var SerialContextKey = &contextKey{"tls-client-serial"}

const tlsHandshakeTimeout = 5 * time.Second

func GetServerTLSConfig(cfg *Config) *tls.Config {
	tlsConfig := &tls.Config{
		GetCertificate: cfg.GetServerCertificate,
		MinVersion:     tls.VersionTLS13,
		ClientAuth:     tls.RequireAnyClientCert,

		VerifyConnection: func(cs tls.ConnectionState) error {
			allowedCerts := cfg.GetAllowedCerts()
			if len(cs.PeerCertificates) == 0 {
				return errors.New("no peer certificate available")
			}

			xCert := cs.PeerCertificates[0]
			receivedCertHash := certs.CertHash(xCert)

			// If this is the first certificate we see, add it to config
			if len(allowedCerts) == 0 {
				cfg.ConfigAddCert(receivedCertHash)
			}

			valid := slices.Contains(allowedCerts, receivedCertHash)
			if !valid {
				slog.Debug("cert not allowed", "allowedCertCount", len(allowedCerts))
				return fmt.Errorf("cert '%s' not found from allowed certs", receivedCertHash)
			}
			return validateClientCertificate(xCert)
		},
	}

	return tlsConfig
}

func GetClientTLSConfig(cfg *Config) *tls.Config {
	return &tls.Config{
		MinVersion:           tls.VersionTLS13,
		GetClientCertificate: cfg.GetClientCertificate,
	}
}

func ConnStateContext(ctx context.Context, c net.Conn) context.Context {
	nc, ok := c.(*tls.Conn)
	if !ok {
		slog.Error("connection is not tls connection")
		c.Close()
		return ctx
	}

	handCtx, cancel := context.WithTimeout(ctx, tlsHandshakeTimeout)
	defer cancel()

	err := nc.HandshakeContext(handCtx)
	if err != nil {
		slog.Error("tls hanshake failure, closing connection", "error", err)
		nc.Close()
		return ctx
	}

	tlsCS := nc.ConnectionState()
	if len(tlsCS.PeerCertificates) == 0 {
		slog.Error("no peer certificates, closing connection")
		nc.Close()
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
		// cert usage might be null for some certs, so allow them
		if len(c.ExtKeyUsage) == 0 {
			return nil
		}
		return x509.CertificateInvalidError{
			Cert:   c,
			Reason: x509.IncompatibleUsage,
			Detail: "must have client auth key usage",
		}
	}
	return nil
}
