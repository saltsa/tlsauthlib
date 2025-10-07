package tlsauthlib

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
	"github.com/saltsa/tlsauthlib/util"
	"github.com/spf13/viper"
)

var currentConfig *Config

const (
	allowedCerts           = "allowed_certs"
	privateKey             = "private_key"
	certificate            = "certificate"
	caCertificate          = "caCertificate"
	configFileName         = "config.yaml"
	defaultApplicationName = "tlsauthlib"
)

type Config struct {
	sync.Mutex
	vi              *viper.Viper
	Port            string
	AllowedCerts    []string `mapstructure:"allowed_certs"`
	ApplicationName string
	TrustDomain     string

	certificate       *tls.Certificate
	caCertificate     *x509.Certificate
	changesPending    bool
	dynamicConfigPath string
}

type options struct {
}
type ConfigOption interface {
	apply(c *options)
}

func NewConfig(opts ...ConfigOption) *Config {
	log.Printf("config loading...")

	vi := viper.NewWithOptions()
	vi.AutomaticEnv()

	newConfig := &Config{
		vi:              vi,
		ApplicationName: defaultApplicationName,
	}
	vi.SetDefault("port", "8443")
	vi.SetDefault("trustDomain", "example.com")

	newConfig.setDynamicConfigPath()
	newConfig.readFromFile()
	newConfig.populateConfig()

	if !newConfig.HasCertificate() {
		certs.CertInit(&certs.CertConfig{
			TrustDomain: newConfig.TrustDomain,
		})

		newConfig.certificate, _ = certs.GetCertificate()
		newConfig.caCertificate = certs.GetCACertificate()
		newConfig.changesPending = true
	}

	newConfig.writeConfigToFile()

	return newConfig
}

func (c *Config) populateConfig() error {
	err := c.vi.Unmarshal(c)
	if err != nil {
		slog.Error("Config umarshal failure", "error", err)
		os.Exit(1)
		return err
	}

	slog.Info("config populating done", "allowedCertCount", len(c.AllowedCerts))

	return nil
}

func (c *Config) ConfigAddCert(cert string) {
	c.Lock()
	defer c.Unlock()

	if len(c.AllowedCerts) > 0 {
		return
	}

	slog.Info("adding new cert to config because no certs configured", "allowedCertCount", len(c.AllowedCerts))

	c.AllowedCerts = append(c.AllowedCerts, cert)
	c.changesPending = true

	go c.writeConfigToFile()
}

func (c *Config) SetTrustDomain(td string) {
	c.Lock()
	defer c.Unlock()
	c.TrustDomain = td
	c.changesPending = true
	go c.writeConfigToFile()
}

func (c *Config) GetAllowedCerts() []string {
	c.Lock()
	defer c.Unlock()
	return c.AllowedCerts
}

func (c *Config) writeConfigToFile() error {
	c.Lock()
	defer c.Unlock()

	if !c.changesPending {
		slog.Info("no changes to config, no need to write to the file", "path", c.dynamicConfigPath)
		return nil
	}

	slog.Info("writing config...", "allowedCertCount", len(c.AllowedCerts), "path", c.dynamicConfigPath)

	c.vi.Set(allowedCerts, c.AllowedCerts)

	keyDERBytes, err := x509.MarshalPKCS8PrivateKey(c.certificate.PrivateKey)
	if err != nil {
		slog.Error("private key marshal failure", "error", err)
		return err
	}

	cert, key := certs.DERToPEM(c.certificate.Leaf.Raw, keyDERBytes)
	c.vi.Set(certificate, string(cert))
	c.vi.Set(privateKey, string(key))

	caCert, _ := certs.DERToPEM(c.caCertificate.Raw, keyDERBytes)
	c.vi.Set(caCertificate, string(caCert))

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
	return c.certificate != nil
}

func (c *Config) GetClientCertificate(cri *tls.CertificateRequestInfo) (*tls.Certificate, error) {
	if !c.HasCertificate() {
		return nil, errors.New("no certificate configured")
	}
	return c.certificate, nil
}

func (c *Config) GetServerCertificate(cri *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if !c.HasCertificate() {
		return nil, errors.New("no certificate configured")
	}
	return c.certificate, nil
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
	dynamicConfigDir := filepath.Join(cacheDir, c.ApplicationName)

	err = os.MkdirAll(dynamicConfigDir, 0700)
	if err != nil {
		log.Fatalln(err)
	}

	c.dynamicConfigPath = filepath.Join(dynamicConfigDir, configFileName)
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

	cert, err1 := util.StringToCert(c.vi.GetString(certificate))
	caCert, err2 := util.StringToCert(c.vi.GetString(caCertificate))
	privateKey, err3 := util.StringToKey(c.vi.GetString(privateKey))

	errGrp := errors.Join(err1, err2, err3)
	if errGrp == nil {
		slog.Info("Certificate, CA certificate and key read from file")
		c.caCertificate = caCert
		c.certificate = util.X509ToTLS(cert)
		c.certificate.PrivateKey = privateKey
		log.Printf("certificate expires in %s", c.certificate.Leaf.NotAfter.Format(time.DateOnly))
	} else {
		slog.Error("no tls certificate found from config", "error", err)
	}

	slog.Info("config read done", "allowedCertCount", len(c.AllowedCerts), "certificateInstalled", c.HasCertificate())
}
