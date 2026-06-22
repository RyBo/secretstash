package cli

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/rybo/secretstash/internal/crypto"
	"github.com/rybo/secretstash/internal/shamir"
)

// stringList collects a repeatable string flag (used by combine's --share).
type stringList []string

func (s *stringList) String() string { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error {
	*s = append(*s, v)
	return nil
}

const defaultAddr = "https://127.0.0.1:8200"

// clientFlags are the global flags shared by every client subcommand.
type clientFlags struct {
	addr       string
	skipVerify bool
	jsonOut    bool
}

func addClientFlags(fs *flag.FlagSet) *clientFlags {
	cf := &clientFlags{}
	addr := os.Getenv("SECRETSTASH_ADDR")
	if addr == "" {
		addr = defaultAddr
	}
	fs.StringVar(&cf.addr, "addr", addr, "server address (env SECRETSTASH_ADDR)")
	fs.BoolVar(&cf.skipVerify, "tls-skip-verify", false, "skip TLS certificate verification (needed for self-signed server certs)")
	fs.BoolVar(&cf.jsonOut, "json", false, "emit raw JSON responses")
	return cf
}

func (cf *clientFlags) httpClient(stderr io.Writer) *http.Client {
	c := &http.Client{Timeout: 15 * time.Second}
	if cf.skipVerify {
		fmt.Fprintln(stderr, "warning: TLS certificate verification disabled")
		c.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}
	return c
}

// call performs one API request, returning the status and decoded body.
func (cf *clientFlags) call(stderr io.Writer, method, path, token string, reqBody any) (int, []byte, error) {
	var body io.Reader
	if reqBody != nil {
		b, err := json.Marshal(reqBody)
		if err != nil {
			return 0, nil, err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, strings.TrimRight(cf.addr, "/")+path, body)
	if err != nil {
		return 0, nil, err
	}
	if reqBody != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("X-Stash-Token", token)
	}
	resp, err := cf.httpClient(stderr).Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, b, err
}

// gone maps an error response to the right exit code and prints the server's
// message to stderr.
func goneExit(stderr io.Writer, status int, body []byte) int {
	var e struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	}
	json.Unmarshal(body, &e)
	if e.Message == "" {
		e.Message = fmt.Sprintf("server returned HTTP %d", status)
	}
	fmt.Fprintln(stderr, "error:", e.Message)
	switch status {
	case http.StatusGone:
		return ExitGone
	case http.StatusNotFound:
		return ExitNotFound
	default:
		return ExitError
	}
}

func cmdWrap(args []string, stdout, stderr io.Writer, stdin *os.File) int {
	fs := flag.NewFlagSet("wrap", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cf := addClientFlags(fs)
	ttl := fs.String("ttl", "", "time-to-live, e.g. 30m, 24h (default: server default)")
	reads := fs.Int("reads", 1, "number of reads before the secret self-destructs")
	shares := fs.Int("shares", 0, "split the token into this many Shamir shares (with --threshold)")
	threshold := fs.Int("threshold", 0, "shares required to reconstruct (quorum); needs --shares")
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}

	// Split mode is opt-in: validate the quorum locally before doing any work.
	splitMode := *shares != 0 || *threshold != 0
	if splitMode && (*shares < 2 || *threshold < 2 || *threshold > *shares || *shares > 255) {
		fmt.Fprintln(stderr, "error: --shares and --threshold must satisfy 2 <= threshold <= shares <= 255")
		return ExitUsage
	}

	var secret string
	switch {
	case fs.NArg() > 1:
		fmt.Fprintln(stderr, "error: expected at most one secret argument")
		return ExitUsage
	case fs.NArg() == 1:
		secret = fs.Arg(0)
	default:
		// No positional arg: read from stdin when piped. Keeps secrets out
		// of shell history: kubectl get secret … | secretstash wrap
		info, err := stdin.Stat()
		if err != nil || info.Mode()&os.ModeCharDevice != 0 {
			fmt.Fprintln(stderr, "error: provide a secret argument or pipe one on stdin")
			return ExitUsage
		}
		b, err := io.ReadAll(io.LimitReader(stdin, 1<<24))
		if err != nil {
			fmt.Fprintln(stderr, "error reading stdin:", err)
			return ExitError
		}
		secret = string(b)
	}
	if secret == "" {
		fmt.Fprintln(stderr, "error: secret is empty")
		return ExitUsage
	}

	req := map[string]any{"secret": secret, "reads": *reads}
	if *ttl != "" {
		req["ttl"] = *ttl
	}
	status, body, err := cf.call(stderr, "POST", "/v1/wrap", "", req)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return ExitError
	}
	if status != http.StatusOK {
		return goneExit(stderr, status, body)
	}
	if cf.jsonOut && !splitMode {
		stdout.Write(body)
		return ExitOK
	}
	var resp struct {
		Token     string    `json:"token"`
		ExpiresAt time.Time `json:"expires_at"`
		Reads     int       `json:"reads"`
		ShareURL  string    `json:"share_url"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		fmt.Fprintln(stderr, "error: bad server response:", err)
		return ExitError
	}

	if splitMode {
		return printShares(stdout, stderr, resp.Token, *shares, *threshold, resp.Reads, resp.ExpiresAt, cf.jsonOut)
	}

	fmt.Fprintln(stdout, "token:     "+resp.Token)
	if resp.ShareURL != "" {
		fmt.Fprintln(stdout, "share url: "+resp.ShareURL)
	}
	fmt.Fprintf(stdout, "reads:     %d\nexpires:   %s\n", resp.Reads, resp.ExpiresAt.Local().Format(time.RFC3339))
	return ExitOK
}

// printShares splits the wrap token into n Shamir shares client-side and prints
// them in place of the single token. The whole token and the single-link share
// URL are deliberately suppressed: either one alone would defeat the split.
func printShares(stdout, stderr io.Writer, token string, n, k, reads int, expires time.Time, jsonOut bool) int {
	raw, err := crypto.ParseToken(token)
	if err != nil {
		fmt.Fprintln(stderr, "error: bad server response:", err)
		return ExitError
	}
	parts, err := shamir.Split(raw, n, k)
	crypto.Wipe(raw)
	if err != nil {
		fmt.Fprintln(stderr, "error: splitting token:", err)
		return ExitError
	}

	if jsonOut {
		out, err := json.Marshal(struct {
			Shares    []string  `json:"shares"`
			Threshold int       `json:"threshold"`
			Reads     int       `json:"reads"`
			ExpiresAt time.Time `json:"expires_at"`
		}{parts, k, reads, expires})
		if err != nil {
			fmt.Fprintln(stderr, "error:", err)
			return ExitError
		}
		stdout.Write(out)
		return ExitOK
	}

	fmt.Fprintf(stdout, "shares (%d of %d required to reconstruct):\n", k, n)
	for _, s := range parts {
		fmt.Fprintln(stdout, "  "+s)
	}
	fmt.Fprintf(stdout, "reads:     %d\nexpires:   %s\n", reads, expires.Local().Format(time.RFC3339))
	fmt.Fprintf(stdout, "\nany %d reconstruct with:  secretstash combine <share> <share> ...\n", k)
	return ExitOK
}

func cmdUnwrap(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("unwrap", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cf := addClientFlags(fs)
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(stderr, "usage: secretstash unwrap <token>")
		return ExitUsage
	}
	return unwrapWithToken(cf, fs.Arg(0), stdout, stderr)
}

// unwrapWithToken consumes one read for token and prints the secret. It is the
// shared tail of unwrap and combine: combine reconstructs a token from shares,
// then hands it here so both commands behave identically.
func unwrapWithToken(cf *clientFlags, token string, stdout, stderr io.Writer) int {
	status, body, err := cf.call(stderr, "POST", "/v1/unwrap", token, nil)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return ExitError
	}
	if status != http.StatusOK {
		return goneExit(stderr, status, body)
	}
	if cf.jsonOut {
		stdout.Write(body)
		return ExitOK
	}
	var resp struct {
		Secret         string `json:"secret"`
		ReadsRemaining int    `json:"reads_remaining"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		fmt.Fprintln(stderr, "error: bad server response:", err)
		return ExitError
	}
	// Raw secret to stdout, metadata to stderr: pipe-safe.
	fmt.Fprint(stdout, resp.Secret)
	if resp.ReadsRemaining > 0 {
		fmt.Fprintf(stderr, "\n%d read(s) remaining\n", resp.ReadsRemaining)
	} else {
		fmt.Fprintln(stderr, "\nfinal read, the secret is now destroyed")
	}
	return ExitOK
}

func cmdCombine(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("combine", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cf := addClientFlags(fs)
	var shareFlags stringList
	fs.Var(&shareFlags, "share", "a share string (repeatable); shares may also be positional args")
	printToken := fs.Bool("print-token", false, "print the reconstructed token instead of unwrapping the secret")
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}

	shares := append([]string(shareFlags), fs.Args()...)
	if len(shares) < 2 {
		fmt.Fprintln(stderr, "usage: secretstash combine <share> <share> [share...]  (or repeat --share)")
		return ExitUsage
	}

	// Reconstruct entirely client-side. A bad/insufficient/corrupted set of
	// shares fails here, before any request reaches the server.
	raw, err := shamir.Combine(shares)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return ExitUsage
	}
	token, err := crypto.EncodeToken(raw)
	crypto.Wipe(raw)
	if err != nil {
		fmt.Fprintln(stderr, "error: reconstructed token is invalid:", err)
		return ExitError
	}

	if *printToken {
		fmt.Fprintln(stdout, token)
		return ExitOK
	}
	return unwrapWithToken(cf, token, stdout, stderr)
}

func cmdPeek(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("peek", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cf := addClientFlags(fs)
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(stderr, "usage: secretstash peek <token>")
		return ExitUsage
	}

	status, body, err := cf.call(stderr, "GET", "/v1/peek", fs.Arg(0), nil)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return ExitError
	}
	if status != http.StatusOK {
		return goneExit(stderr, status, body)
	}
	if cf.jsonOut {
		stdout.Write(body)
		return ExitOK
	}
	var resp struct {
		ExpiresAt      time.Time `json:"expires_at"`
		ReadsRemaining int       `json:"reads_remaining"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		fmt.Fprintln(stderr, "error: bad server response:", err)
		return ExitError
	}
	fmt.Fprintf(stdout, "reads remaining: %d\nexpires:         %s\n",
		resp.ReadsRemaining, resp.ExpiresAt.Local().Format(time.RFC3339))
	return ExitOK
}

func cmdRevoke(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("revoke", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cf := addClientFlags(fs)
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(stderr, "usage: secretstash revoke <token>")
		return ExitUsage
	}

	status, body, err := cf.call(stderr, "DELETE", "/v1/secret", fs.Arg(0), nil)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return ExitError
	}
	if status != http.StatusNoContent {
		return goneExit(stderr, status, body)
	}
	fmt.Fprintln(stdout, "secret revoked")
	return ExitOK
}

func cmdStatus(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cf := addClientFlags(fs)
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}

	status, body, err := cf.call(stderr, "GET", "/v1/sys/health", "", nil)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return ExitError
	}
	if status != http.StatusOK {
		return goneExit(stderr, status, body)
	}
	if cf.jsonOut {
		stdout.Write(body)
		return ExitOK
	}
	var resp struct {
		Status        string `json:"status"`
		Version       string `json:"version"`
		UptimeSeconds int64  `json:"uptime_seconds"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		fmt.Fprintln(stderr, "error: bad server response:", err)
		return ExitError
	}
	fmt.Fprintf(stdout, "server:  %s\nstatus:  %s\nversion: %s\nuptime:  %s\n",
		cf.addr, resp.Status, resp.Version, (time.Duration(resp.UptimeSeconds) * time.Second).String())
	return ExitOK
}
