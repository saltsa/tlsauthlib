package main

import (
	"io"
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/saltsa/tlsauthlib"
	"github.com/saltsa/tlsauthlib/util"
)

var httpClient *http.Client

const maxErrorCount = 3

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
		permErrorCount := 0
		if err := doFetch(cfg.Port); err == nil {
			log.Printf("Requests were success!")
		}

		for range time.Tick(3 * time.Second) {
			if err := doFetch(cfg.Port); err == nil {
				log.Printf("Requests were success!")
			} else {
				uerr, ok := err.(*url.Error)
				if ok {
					if !uerr.Temporary() {
						permErrorCount++
					}
				}
			}
			if permErrorCount > maxErrorCount {
				util.KillMySelf()
			}
		}
	}()

	util.WaitForSignal()
}

func doFetch(port string) error {

	paths := []string{"/", "/testing", "/quit"}

	for _, path := range paths {
		u := "https://localhost:" + port + path
		log.Printf("fetching %s", u)
		resp, err := httpClient.Get(u)
		if err != nil {
			log.Printf("fetch %s failure: %s", u, err)
			return err
		}
		defer resp.Body.Close()
		log.Printf("http status code: %d", resp.StatusCode)

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			log.Printf("failure to read body: %s", err)
			return err
		}

		log.Printf("body: %s", body)
	}
	return nil
}
