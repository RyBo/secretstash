// Package server wires the API, web UI, TLS, and lifecycle together.
package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/rybo/secretstash/internal/api"
	"github.com/rybo/secretstash/internal/store"
	"github.com/rybo/secretstash/internal/version"
	"github.com/rybo/secretstash/internal/web"
)

type Config struct {
	Listen         string // default 127.0.0.1:8200
	TLSCert        string
	TLSKey         string
	Dev            bool // plain HTTP
	DevAllowRemote bool // allow --dev on non-loopback listen
	TrustProxy     bool
	NoUI           bool
	NoMetrics      bool   // disable the /metrics endpoint
	ShareBaseURL   string // override external URL in share links

	API    api.Config
	Limits store.Limits
}

// Run starts the server and blocks until SIGINT/SIGTERM or a fatal error.
func Run(cfg Config) error {
	if cfg.Listen == "" {
		cfg.Listen = "127.0.0.1:8200"
	}
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))

	if cfg.Dev && !cfg.DevAllowRemote && !isLoopback(cfg.Listen) {
		return fmt.Errorf("--dev serves plaintext; refusing non-loopback listen %q without --dev-allow-remote", cfg.Listen)
	}

	tlsCfg, tlsDesc, err := cfg.loadTLS()
	if err != nil {
		return err
	}

	scheme := "https"
	if tlsCfg == nil {
		scheme = "http"
	}
	if cfg.ShareBaseURL == "" {
		cfg.ShareBaseURL = scheme + "://" + cfg.Listen
	}
	cfg.API.ShareBaseURL = strings.TrimRight(cfg.ShareBaseURL, "/")
	api.TrustProxy = cfg.TrustProxy

	st := store.New(cfg.Limits)
	a := api.New(st, cfg.API, logger)

	mux := http.NewServeMux()
	mux.Handle("/v1/", a.Routes())
	if !cfg.NoMetrics {
		// Unauthenticated and outside the rate limiter: restrict at the
		// network level. More specific than "/", so it coexists with the UI.
		mux.HandleFunc("GET /metrics", a.HandleMetrics)
	}
	if !cfg.NoUI {
		mux.Handle("/", web.Handler())
	}

	var handler http.Handler = mux
	handler = api.SecurityHeaders(tlsCfg != nil)(handler)
	handler = api.Recover(logger)(handler)

	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           handler,
		TLSConfig:         tlsCfg,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 * 1024,
		ErrorLog:          slog.NewLogLogger(logger.Handler(), slog.LevelWarn),
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go st.Janitor(ctx, 30*time.Second)

	banner(cfg, scheme, tlsDesc)

	errCh := make(chan error, 1)
	go func() {
		var err error
		if tlsCfg != nil {
			err = srv.ListenAndServeTLS("", "")
		} else {
			err = srv.ListenAndServe()
		}
		if !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
	}

	logger.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return srv.Shutdown(shutdownCtx)
}

func banner(cfg Config, scheme, tlsDesc string) {
	fmt.Fprintf(os.Stderr, `secretstash %s

  listening: %s://%s
  web UI:    %v
  metrics:   %v
  storage:   in-memory only; ALL SECRETS ARE LOST ON RESTART (by design)
  %s

`, version.Version, scheme, cfg.Listen, !cfg.NoUI, metricsDesc(cfg.NoMetrics), tlsDesc)
	if cfg.Dev {
		fmt.Fprintln(os.Stderr, "  WARNING: --dev mode serves PLAINTEXT HTTP. Do not use in production.")
		fmt.Fprintln(os.Stderr)
	}
}

func metricsDesc(noMetrics bool) string {
	if noMetrics {
		return "disabled"
	}
	return "/metrics (unauthenticated; restrict at the network level)"
}

func isLoopback(listen string) bool {
	host, _, err := net.SplitHostPort(listen)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
