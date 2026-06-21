package api

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/rybo/secretstash/internal/store"
)

type testEnv struct {
	srv   *httptest.Server
	api   *API
	logs  *bytes.Buffer
	store *store.Store
}

func newEnv(t *testing.T, cfg Config) *testEnv {
	t.Helper()
	logs := &bytes.Buffer{}
	logger := slog.New(slog.NewJSONHandler(logs, nil))
	st := store.New(store.Limits{})
	a := New(st, cfg, logger)
	srv := httptest.NewServer(a.Routes())
	t.Cleanup(srv.Close)
	return &testEnv{srv: srv, api: a, logs: logs, store: st}
}

func (e *testEnv) wrap(t *testing.T, body string) (int, map[string]any) {
	t.Helper()
	resp, err := http.Post(e.srv.URL+"/v1/wrap", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	return decode(t, resp)
}

func (e *testEnv) do(t *testing.T, method, path, token string) (int, map[string]any) {
	t.Helper()
	req, _ := http.NewRequest(method, e.srv.URL+path, nil)
	if token != "" {
		req.Header.Set(TokenHeader, token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return decode(t, resp)
}

func decode(t *testing.T, resp *http.Response) (int, map[string]any) {
	t.Helper()
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	var m map[string]any
	if len(b) > 0 {
		if err := json.Unmarshal(b, &m); err != nil {
			t.Fatalf("non-JSON response (%d): %s", resp.StatusCode, b)
		}
	}
	return resp.StatusCode, m
}

func TestWrapUnwrapHappyPath(t *testing.T) {
	e := newEnv(t, Config{ShareBaseURL: "https://example.test:8200"})

	code, body := e.wrap(t, `{"secret":"hunter2","ttl":"30m","reads":1}`)
	if code != 200 {
		t.Fatalf("wrap: %d %v", code, body)
	}
	token, _ := body["token"].(string)
	if !strings.HasPrefix(token, "ss.") {
		t.Fatalf("bad token %q", token)
	}
	if share, _ := body["share_url"].(string); !strings.Contains(share, "/s#ss.") {
		t.Fatalf("share_url must carry token in fragment: %q", share)
	}

	code, body = e.do(t, "POST", "/v1/unwrap", token)
	if code != 200 || body["secret"] != "hunter2" {
		t.Fatalf("unwrap: %d %v", code, body)
	}
	if body["reads_remaining"].(float64) != 0 {
		t.Fatalf("want 0 reads remaining, got %v", body["reads_remaining"])
	}
}

func TestSecondUnwrapIsTamperEvident(t *testing.T) {
	e := newEnv(t, Config{})
	_, body := e.wrap(t, `{"secret":"x"}`)
	token := body["token"].(string)

	e.do(t, "POST", "/v1/unwrap", token)
	code, body := e.do(t, "POST", "/v1/unwrap", token)
	if code != http.StatusGone {
		t.Fatalf("want 410, got %d %v", code, body)
	}
	if body["code"] != "consumed" {
		t.Fatalf("want code=consumed, got %v", body["code"])
	}
	if _, err := time.Parse(time.RFC3339, body["consumed_at"].(string)); err != nil {
		t.Fatalf("consumed_at not RFC3339: %v", body["consumed_at"])
	}
	// The tamper alarm must hit the audit log at WARN.
	if !strings.Contains(e.logs.String(), `"level":"WARN"`) ||
		!strings.Contains(e.logs.String(), `"reason":"consumed"`) {
		t.Fatalf("missing WARN consumed audit line:\n%s", e.logs.String())
	}
}

func TestBurnAfterNReads(t *testing.T) {
	e := newEnv(t, Config{})
	_, body := e.wrap(t, `{"secret":"x","reads":3}`)
	token := body["token"].(string)

	for i := 3; i > 0; i-- {
		code, body := e.do(t, "POST", "/v1/unwrap", token)
		if code != 200 || int(body["reads_remaining"].(float64)) != i-1 {
			t.Fatalf("read %d: %d %v", 4-i, code, body)
		}
	}
	code, _ := e.do(t, "POST", "/v1/unwrap", token)
	if code != http.StatusGone {
		t.Fatalf("want 410 after burn, got %d", code)
	}
}

func TestPeekDoesNotConsume(t *testing.T) {
	e := newEnv(t, Config{})
	_, body := e.wrap(t, `{"secret":"x"}`)
	token := body["token"].(string)

	for range 3 {
		code, body := e.do(t, "GET", "/v1/peek", token)
		if code != 200 || body["exists"] != true || body["reads_remaining"].(float64) != 1 {
			t.Fatalf("peek: %d %v", code, body)
		}
	}
	if code, _ := e.do(t, "POST", "/v1/unwrap", token); code != 200 {
		t.Fatalf("unwrap after peeks should succeed, got %d", code)
	}
}

func TestRevoke(t *testing.T) {
	e := newEnv(t, Config{})
	_, body := e.wrap(t, `{"secret":"x"}`)
	token := body["token"].(string)

	code, _ := e.do(t, "DELETE", "/v1/secret", token)
	if code != http.StatusNoContent {
		t.Fatalf("revoke: want 204, got %d", code)
	}
	code, body = e.do(t, "POST", "/v1/unwrap", token)
	if code != http.StatusGone || body["code"] != "revoked" {
		t.Fatalf("want 410 revoked, got %d %v", code, body)
	}
}

func TestUnknownAndMalformedTokens(t *testing.T) {
	e := newEnv(t, Config{})

	// Well-formed but never-issued token → 404.
	fake := "ss." + strings.Repeat("A", 43)
	code, body := e.do(t, "POST", "/v1/unwrap", fake)
	if code != http.StatusNotFound || body["code"] != "not_found" {
		t.Fatalf("want 404 not_found, got %d %v", code, body)
	}

	// Garbage token → 404 (generic; no format oracle).
	code, _ = e.do(t, "POST", "/v1/unwrap", "garbage")
	if code != http.StatusNotFound {
		t.Fatalf("want 404 for malformed token, got %d", code)
	}

	// Missing header → 400.
	code, _ = e.do(t, "POST", "/v1/unwrap", "")
	if code != http.StatusBadRequest {
		t.Fatalf("want 400 for missing header, got %d", code)
	}
}

func TestValidationRejects(t *testing.T) {
	e := newEnv(t, Config{})
	for name, body := range map[string]string{
		"empty secret":   `{"secret":""}`,
		"bad json":       `{`,
		"bad ttl":        `{"secret":"x","ttl":"tomorrow"}`,
		"ttl too long":   `{"secret":"x","ttl":"2000h"}`,
		"ttl too short":  `{"secret":"x","ttl":"1s"}`,
		"reads negative": `{"secret":"x","reads":-1}`,
		"reads too high": `{"secret":"x","reads":1000}`,
	} {
		if code, resp := e.wrap(t, body); code != http.StatusBadRequest {
			t.Errorf("%s: want 400, got %d %v", name, code, resp)
		}
	}
}

func TestOversizeSecret(t *testing.T) {
	e := newEnv(t, Config{MaxSecretSize: 1024})
	big := strings.Repeat("a", 2048)
	code, body := e.wrap(t, `{"secret":"`+big+`"}`)
	// Either the handler's size check (413) or MaxBytesReader (400) is fine,
	// but it must be rejected.
	if code != http.StatusRequestEntityTooLarge && code != http.StatusBadRequest {
		t.Fatalf("want rejection, got %d %v", code, body)
	}
}

func TestExpiredSecret(t *testing.T) {
	e := newEnv(t, Config{MinTTL: time.Millisecond})
	_, body := e.wrap(t, `{"secret":"x","ttl":"50ms"}`)
	token := body["token"].(string)

	time.Sleep(80 * time.Millisecond)
	code, body := e.do(t, "POST", "/v1/unwrap", token)
	if code != http.StatusGone || body["code"] != "expired" {
		t.Fatalf("want 410 expired, got %d %v", code, body)
	}
}

func TestSecurityHeadersAndNoStore(t *testing.T) {
	e := newEnv(t, Config{})
	resp, err := http.Get(e.srv.URL + "/v1/sys/health")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if got := resp.Header.Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control: want no-store, got %q", got)
	}
}

func TestHealth(t *testing.T) {
	e := newEnv(t, Config{})
	code, body := e.do(t, "GET", "/v1/sys/health", "")
	if code != 200 || body["status"] != "ok" {
		t.Fatalf("health: %d %v", code, body)
	}
}

func TestFailedUnwrapRateLimit(t *testing.T) {
	e := newEnv(t, Config{})
	fake := "ss." + strings.Repeat("A", 43)

	// Burn through the 5-failure budget, then expect 429.
	var code int
	for range 10 {
		code, _ = e.do(t, "POST", "/v1/unwrap", fake)
		if code == http.StatusTooManyRequests {
			break
		}
	}
	if code != http.StatusTooManyRequests {
		t.Fatalf("failed unwraps never rate-limited, last code %d", code)
	}
}

func TestTokenNeverInResponsesExceptWrap(t *testing.T) {
	e := newEnv(t, Config{})
	_, body := e.wrap(t, `{"secret":"x","reads":2}`)
	token := body["token"].(string)

	for _, probe := range []struct{ method, path string }{
		{"GET", "/v1/peek"},
		{"POST", "/v1/unwrap"},
	} {
		req, _ := http.NewRequest(probe.method, e.srv.URL+probe.path, nil)
		req.Header.Set(TokenHeader, token)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if bytes.Contains(b, []byte(token)) {
			t.Fatalf("%s %s echoed the token", probe.method, probe.path)
		}
	}
	if strings.Contains(e.logs.String(), token) {
		t.Fatal("token leaked into audit log")
	}
}

func TestAuditLogsEmitted(t *testing.T) {
	e := newEnv(t, Config{})
	_, body := e.wrap(t, `{"secret":"x"}`)
	e.do(t, "POST", "/v1/unwrap", body["token"].(string))

	logs := e.logs.String()
	for _, ev := range []string{`"event":"wrap"`, `"event":"unwrap"`, `"id_prefix":"`} {
		if !strings.Contains(logs, ev) {
			t.Errorf("audit log missing %s:\n%s", ev, logs)
		}
	}
}
