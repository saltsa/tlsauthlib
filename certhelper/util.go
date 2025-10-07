package certhelper

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"os"
	"runtime"
	"time"
)

func DERToPEM(name string, data []byte) []byte {
	buf := new(bytes.Buffer)

	b := &pem.Block{
		Type:  name,
		Bytes: data,
	}
	if err := pem.Encode(buf, b); err != nil {
		log.Fatalf("pem encode failure: %s", err)
	}

	pemBytes := buf.Bytes()
	return pemBytes
}

func PEMToDER(name string, data []byte) ([]byte, error) {
	p, rest := pem.Decode(data)
	if len(rest) > 0 {
		return nil, errors.New("rest not empty")
	}
	if p.Type != name {
		return nil, errors.New("invalid pem type")
	}
	return p.Bytes, nil
}

func PubKeyHashFromPKI(pki []byte) string {
	h := sha256.Sum256(pki)
	pub := hex.EncodeToString(h[:])
	return pub
}

func PublicKeyHashFromCert(raw []byte) string {
	if der, err := PEMToDER("CERTIFICATE", raw); err == nil {
		raw = der
	}
	c, err := x509.ParseCertificate(raw)
	if err != nil {
		log.Fatalln("cert parse failure:", err)
	}
	return PubKeyHashFromPKI(c.RawSubjectPublicKeyInfo)
}

func CertInfo(cert *x509.Certificate) string {
	h := PubKeyHashFromPKI(cert.RawSubjectPublicKeyInfo)
	expIn := time.Until(cert.NotAfter)
	return fmt.Sprintf("serial=%.6s... pubkey=%.6s... expiresIn=%s", cert.SerialNumber.String(), h, expIn)
}

func MustReadCert(name string) *x509.Certificate {
	raw, err := os.ReadFile(name)
	if err != nil {
		panic(err)
	}
	if der, err := PEMToDER("CERTIFICATE", raw); err == nil {
		raw = der
	}
	cert, err := x509.ParseCertificate(raw)
	if err != nil {
		panic(err)
	}
	return cert
}

// Use this like `defer TimeFunction()()`
func TimeFunction(fn string) func() {
	start := time.Now()
	return func() {
		end := time.Now()

		var pcs [1]uintptr
		runtime.Callers(2, pcs[:])
		pc := pcs[0]
		record := slog.NewRecord(end, slog.LevelDebug, fmt.Sprintf("function %s executed in %s", fn, end.Sub(start)), pc)

		slog.Default().Handler().Handle(context.Background(), record)
	}
}
