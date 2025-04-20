package main

import (
	"io"
	"log"
	"net/http"
	"time"

	"github.com/saltsa/tlsauthlib"
	"github.com/saltsa/tlsauthlib/util"
)

var httpClient *http.Client

func main() {
	util.LogInit()

	cfg := util.InitConfig()

	httpClient = &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:   tlsauthlib.GetClientTLSConfig(cfg),
			ForceAttemptHTTP2: true,
		},
	}

	go func() {
		if err := doFetch(cfg.Port); err == nil {
			log.Printf("Requests were success!")
		}

		for range time.Tick(3 * time.Second) {
			if err := doFetch(cfg.Port); err == nil {
				log.Printf("Requests were success!")
			}
		}
	}()

	util.WaitForSignal()
}

func doFetch(port string) error {

	paths := []string{"/", "/testing", "/quit"}

	for _, path := range paths {
		resp, err := httpClient.Get("https://localhost:" + port + path)
		if err != nil {
			log.Printf("fetch failure: %s", err)
			return err
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)

		if resp.StatusCode != http.StatusOK {
			log.Printf("status: %d", resp.StatusCode)
		}

		log.Printf("body: %s", body)
	}
	return nil
}
