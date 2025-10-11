package mtlscfg

import (
	"crypto/x509"
	"fmt"
	"strings"
)

func verifyCertificateIdentity(pcs []*x509.Certificate, coordinationServer string, expectedIdentity string) error {
	role, err := getRoleFromCert(pcs, coordinationServer)
	if err != nil {
		return err
	}
	if expectedIdentity != "" && role != expectedIdentity {
		return fmt.Errorf("remote identity %q does not match expected %q", role, expectedIdentity)
	}
	return nil
}

func getRoleFromCert(pcs []*x509.Certificate, coordinationServer string) (string, error) {
	if len(pcs) == 0 {
		return "", ErrNoTLSCert
	}
	pc := pcs[0]

	if len(pc.URIs) != 1 {
		return "", ErrInvalidNumberOfURIs
	}
	roleURI := pc.URIs[0]

	if roleURI.Scheme != "spiffe" {
		return "", ErrInvalidURIScheme
	}

	if roleURI.Host != coordinationServer {
		return "", ErrInvalidHost
	}

	if len(roleURI.Path) == 0 {
		return "", ErrInvalidPath
	}

	return strings.TrimPrefix(roleURI.Path, "/"), nil
}
