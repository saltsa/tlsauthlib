package util

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"log"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/saltsa/tlsauthlib/internal/certs"

	"github.com/spf13/viper"
)

var currentConfig *Config

const (
	allowedCerts   = "allowed_certs"
	privateKey     = "private_key"
	certificate    = "certificate"
	configFileName = "config.yaml"
)

type Config struct {
	sync.Mutex
	vi                *viper.Viper
	Port              string
	AllowedCerts      []string `mapstructure:"allowed_certs"`
	Certificate       *tls.Certificate
	changesPending    bool
	dynamicConfigPath string
}

func (c *Config) readFromFile() {
	c.Lock()
	defer c.Unlock()
	slog.Debug("reading config...", "allowedCertCount", len(c.AllowedCerts), "path", c.dynamicConfigPath)

	c.vi.SetConfigType("yaml")
	c.vi.SetConfigFile(c.dynamicConfigPath)
	c.vi.ReadInConfig()

	err := c.vi.ReadInConfig()
	if err != nil {
		slog.Error("Config read failure", "error", err)
	}

	cert := c.vi.GetString(certificate)
	privateKey := c.vi.GetString(privateKey)
	if len(cert) > 0 && len(privateKey) > 0 {
		tlsCert, err := tls.X509KeyPair([]byte(cert), []byte(privateKey))
		if err != nil {
			log.Fatalf("failed to read cert: %s", err)
		}
		c.Certificate = &tlsCert
		log.Printf("certificate expires in %s", c.Certificate.Leaf.NotAfter.Format(time.DateOnly))
	} else {
		slog.Error("no tls certificate found from config", "error", err)
	}

	slog.Info("config read done", "allowedCertCount", len(c.AllowedCerts), "certificateInstalled", c.HasCertificate())
}

func InitConfig() *Config {
	log.Printf("config loading...")

	vi := viper.NewWithOptions()
	vi.AutomaticEnv()

	// viper.WithLogger(slog.Default())

	newConfig := &Config{
		vi: vi,
	}
	vi.SetDefault("port", "8443")

	newConfig.setDynamicConfigPath()
	newConfig.readFromFile()
	newConfig.populateConfig()

	if !newConfig.HasCertificate() {
		certs.CertInit()
		cert, err := certs.GetCertificate()
		if err != nil {
			log.Fatalf("failure to get client cert: %s", err)
		}

		newConfig.Certificate = cert
		newConfig.changesPending = true
	}

	newConfig.Commit()

	return newConfig
}

func (c *Config) populateConfig() error {
	err := c.vi.Unmarshal(c)
	if err != nil {
		slog.Error("Config umarshal failure", "error", err)
		return err
	}

	slog.Info("config populating done", "allowedCertCount", len(c.AllowedCerts))

	return nil
}

func (c *Config) ConfigAddCert(cert string) {
	c.Lock()
	defer c.Unlock()
	slog.Debug("adding new cert to config...", "allowedCertCount", len(c.AllowedCerts))
	if len(c.AllowedCerts) > 0 {
		return
	}

	c.AllowedCerts = append(c.AllowedCerts, cert)
	c.changesPending = true

	go c.Commit()
}

func (c *Config) GetAllowedCerts() []string {
	c.Lock()
	defer c.Unlock()
	return c.AllowedCerts
}
func (c *Config) Commit() error {
	c.Lock()
	defer c.Unlock()

	slog.Info("writing config...", "allowedCertCount", len(c.AllowedCerts), "path", c.dynamicConfigPath)

	if !c.changesPending {
		slog.Info("no changes to config, no write to file")
		return nil
	}

	c.vi.Set(allowedCerts, c.AllowedCerts)

	keyDERBytes, err := x509.MarshalPKCS8PrivateKey(c.Certificate.PrivateKey)
	if err != nil {
		slog.Error("private key marshal failure", "error", err)
		return err
	}

	cert, key := certs.DERToPEM(c.Certificate.Leaf.Raw, keyDERBytes)
	c.vi.Set(certificate, string(cert))
	c.vi.Set(privateKey, string(key))

	err = c.vi.WriteConfigAs(c.dynamicConfigPath)
	if err != nil {
		slog.Error("config write failure", "error", err)
		return err
	}
	slog.Info("config successfully saved", "allowedCertCount", len(c.AllowedCerts))
	c.changesPending = false
	return nil
}

func (c *Config) HasCertificate() bool {
	return c.Certificate != nil
}

func (c *Config) GetClientCertificate(cri *tls.CertificateRequestInfo) (*tls.Certificate, error) {
	if !c.HasCertificate() {
		return nil, errors.New("no certificate configured")
	}
	return c.Certificate, nil
}

func (c *Config) GetServerCertificate(cri *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if !c.HasCertificate() {
		return nil, errors.New("no certificate configured")
	}
	return c.Certificate, nil
}

func (c *Config) setDynamicConfigPath() {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		log.Fatalln(err)
	}
	configDir, err := os.UserConfigDir()
	if err != nil {
		log.Fatalln(err)
	}
	cacheDir, err := os.UserCacheDir()
	if err != nil {
		log.Fatalln(err)
	}

	slog.Debug("directories from environment", "cache", cacheDir, "config", configDir, "home", homeDir)
	dynamicConfigDir := filepath.Join(cacheDir, "tlsauthlib")
	err = os.MkdirAll(dynamicConfigDir, 0700)
	if err != nil {
		log.Fatalln(err)
	}

	c.dynamicConfigPath = filepath.Join(dynamicConfigDir, configFileName)
}
