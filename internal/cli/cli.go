// Package cli implements the secretstash command-line interface: the server
// subcommand plus client commands speaking to a running server.
package cli

import (
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/rybo/secretstash/internal/api"
	"github.com/rybo/secretstash/internal/server"
	"github.com/rybo/secretstash/internal/store"
	"github.com/rybo/secretstash/internal/version"
)

// Exit codes. ExitGone (consumed/expired/revoked) is distinct so scripts can
// branch on tamper evidence.
const (
	ExitOK       = 0
	ExitError    = 1
	ExitUsage    = 2
	ExitGone     = 3
	ExitNotFound = 4
)

const usage = `secretstash: share secrets via one-time self-destructing links

Usage: secretstash <command> [flags]

Server:
  server      run the secretstash server (REST API + web UI)

Client (set SECRETSTASH_ADDR or --addr, default https://127.0.0.1:8200):
  wrap        wrap a secret, print its one-time token and share link
  unwrap      consume a read and print the secret to stdout
  peek        show a secret's metadata without consuming a read
  revoke      destroy a secret before it is read
  status      check server health
  version     print the client version

Run "secretstash <command> -h" for command flags.
`

// Run executes the CLI and returns the process exit code. Output streams are
// parameterized in runIO for tests.
func Run(args []string) int {
	return runIO(args, os.Stdout, os.Stderr, os.Stdin)
}

func runIO(args []string, stdout, stderr io.Writer, stdin *os.File) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return ExitUsage
	}
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "server":
		return cmdServer(rest, stderr)
	case "wrap":
		return cmdWrap(rest, stdout, stderr, stdin)
	case "unwrap":
		return cmdUnwrap(rest, stdout, stderr)
	case "peek":
		return cmdPeek(rest, stdout, stderr)
	case "revoke":
		return cmdRevoke(rest, stdout, stderr)
	case "status":
		return cmdStatus(rest, stdout, stderr)
	case "version":
		fmt.Fprintln(stdout, "secretstash "+version.Version)
		return ExitOK
	case "-h", "--help", "help":
		fmt.Fprint(stdout, usage)
		return ExitOK
	default:
		fmt.Fprintf(stderr, "unknown command %q\n\n%s", cmd, usage)
		return ExitUsage
	}
}

func cmdServer(args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet("server", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var cfg server.Config
	fs.StringVar(&cfg.Listen, "listen", "127.0.0.1:8200", "listen address")
	fs.StringVar(&cfg.TLSCert, "tls-cert", "", "TLS certificate file (with -tls-key)")
	fs.StringVar(&cfg.TLSKey, "tls-key", "", "TLS private key file (with -tls-cert)")
	fs.BoolVar(&cfg.Dev, "dev", false, "serve plaintext HTTP (development only)")
	fs.BoolVar(&cfg.DevAllowRemote, "dev-allow-remote", false, "allow -dev on a non-loopback address")
	fs.StringVar(&cfg.RealIPHeader, "real-ip-header", "", "trust this proxy-set header for the client IP, e.g. CF-Connecting-IP (only when the origin is reachable solely via that proxy)")
	trustProxy := fs.Bool("trust-proxy", false, "deprecated: alias for -real-ip-header X-Forwarded-For")
	fs.BoolVar(&cfg.NoUI, "no-ui", false, "disable the web UI")
	fs.BoolVar(&cfg.NoMetrics, "no-metrics", false, "disable the /metrics endpoint")
	fs.StringVar(&cfg.ShareBaseURL, "share-base-url", "", "external base URL used in share links (default derived from listen address)")

	maxSecretSize := fs.Int("max-secret-size", 64*1024, "maximum secret size in bytes")
	maxSecrets := fs.Int("max-secrets", 10000, "maximum number of live secrets")
	defaultTTL := fs.Duration("default-ttl", 24*time.Hour, "TTL when the client does not specify one")
	maxTTL := fs.Duration("max-ttl", 168*time.Hour, "maximum allowed TTL")
	maxReads := fs.Int("max-reads", 100, "maximum allowed reads per secret")

	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}

	// -trust-proxy is a deprecated alias: it now trusts X-Forwarded-For via the
	// same safe (rightmost-hop) path as -real-ip-header, replacing the old
	// spoofable first-hop logic.
	if *trustProxy && cfg.RealIPHeader == "" {
		cfg.RealIPHeader = "X-Forwarded-For"
		fmt.Fprintln(stderr, "warning: -trust-proxy is deprecated; use -real-ip-header X-Forwarded-For (or CF-Connecting-IP behind Cloudflare)")
	}

	cfg.API = api.Config{
		DefaultTTL:    *defaultTTL,
		MaxTTL:        *maxTTL,
		MaxReads:      *maxReads,
		MaxSecretSize: *maxSecretSize,
	}
	cfg.Limits = store.Limits{MaxSecrets: *maxSecrets}

	if err := server.Run(cfg); err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return ExitError
	}
	return ExitOK
}
