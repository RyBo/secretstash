package cli

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/rybo/secretstash/internal/api"
	"github.com/rybo/secretstash/internal/store"
)

// run executes the CLI against a test server, capturing output streams.
func run(t *testing.T, srvURL string, stdin *os.File, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errBuf bytes.Buffer
	full := append([]string{args[0], "--addr", srvURL}, args[1:]...)
	if stdin == nil {
		stdin, _ = os.Open(os.DevNull)
		defer stdin.Close()
	}
	code = runIO(full, &out, &errBuf, stdin)
	return code, out.String(), errBuf.String()
}

func newServer(t *testing.T) *httptest.Server {
	t.Helper()
	st := store.New(store.Limits{})
	a := api.New(st, api.Config{}, slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})))
	srv := httptest.NewServer(a.Routes())
	t.Cleanup(srv.Close)
	return srv
}

func tokenFrom(t *testing.T, stdout string) string {
	t.Helper()
	for _, line := range strings.Split(stdout, "\n") {
		if rest, ok := strings.CutPrefix(line, "token:"); ok {
			return strings.TrimSpace(rest)
		}
	}
	t.Fatalf("no token in output:\n%s", stdout)
	return ""
}

func TestWrapUnwrapRoundTrip(t *testing.T) {
	srv := newServer(t)

	code, stdout, _ := run(t, srv.URL, nil, "wrap", "--ttl", "5m", "the payload")
	if code != ExitOK {
		t.Fatalf("wrap exit %d", code)
	}
	token := tokenFrom(t, stdout)

	code, stdout, stderr := run(t, srv.URL, nil, "unwrap", token)
	if code != ExitOK {
		t.Fatalf("unwrap exit %d: %s", code, stderr)
	}
	// Raw secret on stdout, nothing else.
	if stdout != "the payload" {
		t.Fatalf("stdout %q, must be the raw secret only", stdout)
	}
	if !strings.Contains(stderr, "destroyed") {
		t.Fatalf("metadata missing from stderr: %q", stderr)
	}
}

func TestSecondUnwrapExitsGone(t *testing.T) {
	srv := newServer(t)
	_, stdout, _ := run(t, srv.URL, nil, "wrap", "x")
	token := tokenFrom(t, stdout)

	run(t, srv.URL, nil, "unwrap", token)
	code, _, stderr := run(t, srv.URL, nil, "unwrap", token)
	if code != ExitGone {
		t.Fatalf("want exit %d (gone), got %d", ExitGone, code)
	}
	if !strings.Contains(stderr, "already consumed") {
		t.Fatalf("missing tamper message: %q", stderr)
	}
}

func TestUnknownTokenExitsNotFound(t *testing.T) {
	srv := newServer(t)
	code, _, _ := run(t, srv.URL, nil, "unwrap", "ss."+strings.Repeat("B", 43))
	if code != ExitNotFound {
		t.Fatalf("want exit %d, got %d", ExitNotFound, code)
	}
}

func TestWrapFromStdin(t *testing.T) {
	srv := newServer(t)

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	w.WriteString("piped secret\n")
	w.Close()
	defer r.Close()

	code, stdout, stderr := run(t, srv.URL, r, "wrap")
	if code != ExitOK {
		t.Fatalf("wrap from stdin exit %d: %s", code, stderr)
	}
	token := tokenFrom(t, stdout)

	_, stdout, _ = run(t, srv.URL, nil, "unwrap", token)
	if stdout != "piped secret\n" {
		t.Fatalf("got %q", stdout)
	}
}

func TestPeekAndRevoke(t *testing.T) {
	srv := newServer(t)
	_, stdout, _ := run(t, srv.URL, nil, "wrap", "--reads", "2", "x")
	token := tokenFrom(t, stdout)

	code, stdout, _ := run(t, srv.URL, nil, "peek", token)
	if code != ExitOK || !strings.Contains(stdout, "reads remaining: 2") {
		t.Fatalf("peek: %d %q", code, stdout)
	}

	if code, _, _ = run(t, srv.URL, nil, "revoke", token); code != ExitOK {
		t.Fatalf("revoke exit %d", code)
	}
	code, _, _ = run(t, srv.URL, nil, "unwrap", token)
	if code != ExitGone {
		t.Fatalf("unwrap after revoke: want %d, got %d", ExitGone, code)
	}
}

func TestStatusAndJSON(t *testing.T) {
	srv := newServer(t)
	code, stdout, _ := run(t, srv.URL, nil, "status", "--json")
	if code != ExitOK {
		t.Fatalf("status exit %d", code)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(stdout), &m); err != nil || m["status"] != "ok" {
		t.Fatalf("bad json status output: %q", stdout)
	}
}

func TestUsageErrors(t *testing.T) {
	for _, args := range [][]string{
		{},
		{"bogus-command"},
		{"unwrap"},          // missing token
		{"wrap", "a", "b"},  // too many args
	} {
		var out, errBuf bytes.Buffer
		devnull, _ := os.Open(os.DevNull)
		code := runIO(args, &out, &errBuf, devnull)
		devnull.Close()
		if code != ExitUsage {
			t.Errorf("args %v: want exit %d, got %d", args, ExitUsage, code)
		}
	}
}

func TestVersion(t *testing.T) {
	var out, errBuf bytes.Buffer
	if code := runIO([]string{"version"}, &out, &errBuf, nil); code != ExitOK {
		t.Fatalf("version exit %d", code)
	}
	if !strings.HasPrefix(out.String(), "secretstash ") {
		t.Fatalf("got %q", out.String())
	}
}
