package main

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"syscall"
	"time"

	"github.com/saltsa/tlsauthlib"
	"github.com/saltsa/tlsauthlib/util"
)

func main() {
	// inits
	util.LogInit()
	cfg := util.InitConfig()

	// example http handler
	http.HandleFunc("/", httpHandler)
	http.HandleFunc("/quit", httpQuitHandler)

	// configure server properly
	srv := &http.Server{
		ReadTimeout: 3 * time.Second,
		Addr:        "localhost:" + cfg.Port,
		TLSConfig:   tlsauthlib.GetServerTLSConfig(cfg),
		ConnContext: tlsauthlib.ConnStateContext,
	}

	log.Printf("start listen at %s", srv.Addr)
	ln, err := net.Listen("tcp", srv.Addr)
	if err != nil {
		log.Fatalf("failure to listen: %s", err)
	}

	// TODO: signal that we're now ready to accept connections

	go func() {
		defer ln.Close()

		err := srv.ServeTLS(ln, "", "")
		if err == http.ErrServerClosed {
			log.Printf("server closed normally")
			return
		}
		log.Fatalf("failure to server TLS: %s", err)
	}()

	// shuts down srv gracefully if term signal is received
	util.WaitForSignal(srv)
}

// example handler outputting client certificate serial
func httpHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("hello world\n"))
	serial := r.Context().Value(tlsauthlib.SerialContextKey).(string)
	fmt.Fprintf(w, "tls cert serial was: %s\n", serial)
	// log.Printf("tls cert serial was: %s\n", serial)
}

func httpQuitHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("http quit endpoint called")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("thank you for playing\n"))
	go func() {
		syscall.Kill(os.Getpid(), syscall.SIGINT)
	}()

	for i := 10; i > 0; i-- {
		fmt.Fprintf(w, "count down %d\n", i)
		w.(http.Flusher).Flush()
		time.Sleep(1 * time.Second)
	}
}
