// Command demail-bridge runs the inbound Web2->Web3 mail bridge: it receives
// Resend inbound webhooks, verifies them, routes by recipient domain to the
// owning org, and mints an encrypted Message on-chain to the target agent.
//
// Config is a JSON file (path via -config or DEMAIL_CONFIG); the webhook
// signing secret is read from DEMAIL_WEBHOOK_SECRET so no credential lives in
// the config file. Signing keys must be present in the host's sui keystore.
package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/fractalmind-ai/fractal-demail/bridge"
)

func main() {
	configPath := flag.String("config", os.Getenv("DEMAIL_CONFIG"), "path to JSON config")
	flag.Parse()
	log := slog.Default()

	if *configPath == "" {
		log.Error("config path required (-config or DEMAIL_CONFIG)")
		os.Exit(2)
	}
	secret := os.Getenv("DEMAIL_WEBHOOK_SECRET")
	if secret == "" {
		log.Error("DEMAIL_WEBHOOK_SECRET required")
		os.Exit(2)
	}
	cfg, err := bridge.LoadRelayerConfig(*configPath)
	if err != nil {
		log.Error("load config", "err", err)
		os.Exit(1)
	}
	srv, err := cfg.BuildServer(secret)
	if err != nil {
		log.Error("build server", "err", err)
		os.Exit(1)
	}
	bind := cfg.Bind
	if bind == "" {
		bind = ":8080"
	}
	httpSrv := &http.Server{
		Addr:              bind,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		log.Info("demail-bridge listening", "bind", bind, "orgs", len(cfg.Orgs))
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("server", "err", err)
			os.Exit(1)
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = httpSrv.Shutdown(ctx)
	log.Info("demail-bridge stopped")
}
