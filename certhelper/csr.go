package certhelper

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"log/slog"
	"net"
	"os"
)

const country = "FI"

func GenCSR(key crypto.Signer) ([]byte, error) {
	defer TimeFunction("GenCSR")()
	logger := slog.Default()

	hostname, err := os.Hostname()
	if err != nil {
		return nil, err
	}

	var ips []net.IP

	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			return nil, err
		}
		for _, addr := range addrs {
			ip, _, err := net.ParseCIDR(addr.String())
			if err != nil {
				continue
			}
			if ip.IsLinkLocalUnicast() || ip.IsLoopback() {
				continue
			}
			logger.Debug("found network interface", "iface", iface.Name, "mac", iface.HardwareAddr.String(), "ip", ip.String())

			ips = append(ips, ip)
		}
	}

	logger.Debug("ip addresses found", "addresses", ips)

	template := &x509.CertificateRequest{
		DNSNames:    []string{hostname},
		IPAddresses: ips,
		Subject: pkix.Name{
			Country:    []string{country},
			CommonName: hostname,
		},
	}

	resp, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	if err != nil {
		return nil, err
	}

	logger.Debug("csr created", "template", template)
	return resp, nil
}
