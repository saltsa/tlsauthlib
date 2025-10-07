package certhelper

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"log/slog"
	"os"
)

func GenPrivKey() (crypto.Signer, []byte, error) {
	logger := slog.Default()
	logger.Info("generating new private key")
	newPrivKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	pkBytes, err := x509.MarshalPKCS8PrivateKey(newPrivKey)
	if err != nil {
		return nil, nil, err
	}

	return newPrivKey, pkBytes, nil

}

func readPrivateKey(keyFile string) (crypto.Signer, error) {
	f, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, err
	}

	pkBytes, err := PEMToDER("PRIVATE KEY", f)
	if err != nil {
		return nil, err
	}

	pk, err := x509.ParsePKCS8PrivateKey(pkBytes)
	if err != nil {
		return nil, err
	}
	return pk.(crypto.Signer), nil
}

func MustGetPrivKey(keyFile string) crypto.Signer {
	defer TimeFunction("MustGetPrivKey")()

	if _, err := os.Stat(keyFile); !os.IsNotExist(err) {
		pk, err := readPrivateKey(keyFile)
		if err != nil {
			panic(err)
		}
		return pk
	}
	pk, pkBytes, err := GenPrivKey()
	if err != nil {
		panic(err)
	}

	err = writePrivateKey(keyFile, pkBytes)
	if err != nil {
		panic(err)
	}

	return pk
}

func writePrivateKey(filename string, data []byte) error {
	logger := slog.Default()

	f, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()

	if _, err = f.Write(DERToPEM("PRIVATE KEY", data)); err != nil {
		return err
	}

	logger.Info("new private key saved to file", "filename", filename)
	return nil
}
