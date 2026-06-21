package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// scrape calls HandleMetrics directly: /metrics is registered on the server's
// root mux, not in Routes(), so the testEnv's httptest server does not serve it.
func (e *testEnv) scrape(t *testing.T) (string, http.Header) {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/metrics", nil)
	e.api.HandleMetrics(rec, req)
	if rec.Code != 200 {
		t.Fatalf("metrics: status %d", rec.Code)
	}
	return rec.Body.String(), rec.Header()
}

func mustContain(t *testing.T, body, line string) {
	t.Helper()
	for _, l := range strings.Split(body, "\n") {
		if l == line {
			return
		}
	}
	t.Fatalf("metrics missing line %q in:\n%s", line, body)
}

func TestMetricsExposition(t *testing.T) {
	e := newEnv(t, Config{})

	body, hdr := e.scrape(t)
	if ct := hdr.Get("Content-Type"); !strings.HasPrefix(ct, "text/plain; version=0.0.4") {
		t.Fatalf("content-type = %q", ct)
	}
	// build_info is always present with the version label.
	if !strings.Contains(body, `secretstash_build_info{version="dev"} 1`) {
		t.Fatalf("missing build_info:\n%s", body)
	}
	// Every counter publishes its HELP/TYPE even at zero.
	mustContain(t, body, "# TYPE secretstash_wraps_total counter")
	mustContain(t, body, "secretstash_wraps_total 0")
	mustContain(t, body, "secretstash_live_secrets 0")
}

func TestMetricsCountsLifecycle(t *testing.T) {
	e := newEnv(t, Config{})

	// Two wraps; consume one fully, leave one live.
	_, b1 := e.wrap(t, `{"secret":"a"}`)
	token := b1["token"].(string)
	e.wrap(t, `{"secret":"b"}`)

	e.do(t, "POST", "/v1/unwrap", token) // success, burns it
	e.do(t, "POST", "/v1/unwrap", token) // already consumed -> failure
	e.do(t, "GET", "/v1/peek", token)    // consumed -> failure (peek of gone)

	body, _ := e.scrape(t)
	mustContain(t, body, "secretstash_wraps_total 2")
	mustContain(t, body, "secretstash_unwraps_total 1")
	mustContain(t, body, `secretstash_unwrap_failures_total{reason="consumed"} 2`)
	mustContain(t, body, "secretstash_live_secrets 1")
	mustContain(t, body, "secretstash_tombstones 1")
}

func TestMetricsCountsPeekAndAuthFail(t *testing.T) {
	e := newEnv(t, Config{})

	_, b := e.wrap(t, `{"secret":"x"}`)
	token := b["token"].(string)

	e.do(t, "GET", "/v1/peek", token)        // live peek -> counted
	e.do(t, "POST", "/v1/unwrap", "garbage") // unparseable token -> auth_fail

	body, _ := e.scrape(t)
	mustContain(t, body, "secretstash_peeks_total 1")
	mustContain(t, body, `secretstash_unwrap_failures_total{reason="auth_fail"} 1`)
}

func TestMetricsQuoteEscaping(t *testing.T) {
	got := quote(`a"b\c` + "\n")
	want := `"a\"b\\c\n"`
	if got != want {
		t.Fatalf("quote = %q, want %q", got, want)
	}
}
