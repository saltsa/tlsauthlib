package util

import (
	"context"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func WaitForSignal(srvs ...*http.Server) {
	sc := make(chan os.Signal, 1)
	signal.Notify(sc, os.Interrupt, os.Kill, syscall.SIGTERM, syscall.SIGINT)

	log.Printf("waiting for signal...")
	sig := <-sc

	log.Printf("received signal: %s", sig)

	if len(srvs) > 0 {
		srv := srvs[0]
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()

		err := srv.Shutdown(ctx)
		if err != nil {
			log.Printf("srv shutdown err %v", err)
		}
	}
	log.Printf("shutdown complete")
}

func LogInit() {
	// fd, err := os.OpenFile("/tmp/tlsauth.log", os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	// if err != nil {
	// 	log.Fatalf("log file open failure: %s", err)
	// }
	h := newMultilogHandler(
		slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
			Level:     slog.LevelDebug,
			AddSource: true,
		}),
	// slog.NewJSONHandler(fd, &slog.HandlerOptions{
	// 	Level: slog.LevelDebug,
	// }),
	)
	l := slog.New(h)

	slog.SetLogLoggerLevel(slog.LevelDebug)
	slog.SetDefault(l)
}
