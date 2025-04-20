package util

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"log"
)

func KeytoString(key crypto.PrivateKey) string {
	pkcs, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		log.Fatalf("failure to marshal pk: %s", err)
	}

	p := pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: pkcs,
	}

	ret := string(pem.EncodeToMemory(&p))

	return ret
}

func CertToString(cert *x509.Certificate) string {
	p := pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}
	ret := string(pem.EncodeToMemory(&p))
	return ret
}

func StringToCert(cert string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(cert))
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("not a certificate")
	}
	return x509.ParseCertificate(block.Bytes)
}

func StringToKey(key string) (crypto.PrivateKey, error) {
	block, _ := pem.Decode([]byte(key))
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, errors.New("not a private key")
	}
	return x509.ParsePKCS8PrivateKey(block.Bytes)
}

func X509ToTLS(cert *x509.Certificate) *tls.Certificate {
	return &tls.Certificate{
		Certificate: [][]byte{cert.Raw},
		Leaf:        cert,
	}
}
