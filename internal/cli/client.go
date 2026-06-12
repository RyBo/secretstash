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
)

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
	if err := fs.Parse(args); err != nil {
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
	if cf.jsonOut {
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
	fmt.Fprintln(stdout, "token:     "+resp.Token)
	if resp.ShareURL != "" {
		fmt.Fprintln(stdout, "share url: "+resp.ShareURL)
	}
	fmt.Fprintf(stdout, "reads:     %d\nexpires:   %s\n", resp.Reads, resp.ExpiresAt.Local().Format(time.RFC3339))
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

	status, body, err := cf.call(stderr, "POST", "/v1/unwrap", fs.Arg(0), nil)
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
