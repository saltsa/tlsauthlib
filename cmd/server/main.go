package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/saltsa/tlsauthlib"
	"github.com/saltsa/tlsauthlib/util"
)

const tlsSerialContext = "tls-serial"

func main() {
	// inits
	util.LogInit()
	cfg := util.InitConfig()

	// example http handler
	http.HandleFunc("/", httpHandler)

	// configure server properly
	srv := &http.Server{
		ReadTimeout: 3 * time.Second,
		Addr:        "localhost:" + cfg.Port,
		TLSConfig:   tlsauthlib.GetServerTLSConfig(cfg),
		ConnContext: tlsauthlib.ConnStateContext,
	}

	// shuts down srv gracefully if term signal is received
	go util.WaitForSignal(srv)

	log.Printf("start listen at %s", srv.Addr)
	err := srv.ListenAndServeTLS("", "")
	if err == http.ErrServerClosed {
		log.Printf("server shut down normally")
		os.Exit(0)
	}
	log.Fatalf("failure to listen: %s", err)
}

// example handler outputting client certificate serial
func httpHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("hello world\n"))
	serial := r.Context().Value(tlsauthlib.SerialContextKey).(string)
	fmt.Fprintf(w, "tls cert serial was: %s\n", serial)
	// log.Printf("tls cert serial was: %s\n", serial)
}
