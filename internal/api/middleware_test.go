package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// setRealIPHeader sets the package global for the duration of a test and
// restores it afterward. These tests therefore cannot run in parallel.
func setRealIPHeader(t *testing.T, name string) {
	t.Helper()
	prev := RealIPHeader
	RealIPHeader = name
	t.Cleanup(func() { RealIPHeader = prev })
}

func TestRemoteIP(t *testing.T) {
	const socketIP = "192.0.2.10" // request RemoteAddr host

	cases := []struct {
		name   string
		header string // RealIPHeader to trust ("" = trust nothing)
		set    map[string]string
		want   string
	}{
		{
			name: "no trusted header ignores forwarded headers",
			set:  map[string]string{"CF-Connecting-IP": "203.0.113.7"},
			want: socketIP,
		},
		{
			name:   "single value header honored",
			header: "CF-Connecting-IP",
			set:    map[string]string{"CF-Connecting-IP": "203.0.113.7"},
			want:   "203.0.113.7",
		},
		{
			name:   "rightmost hop wins over spoofed first hop",
			header: "X-Forwarded-For",
			set:    map[string]string{"X-Forwarded-For": "9.9.9.9, 203.0.113.7"},
			want:   "203.0.113.7",
		},
		{
			name:   "trims whitespace around value",
			header: "X-Real-IP",
			set:    map[string]string{"X-Real-IP": "  203.0.113.7  "},
			want:   "203.0.113.7",
		},
		{
			name:   "IPv6 value honored",
			header: "CF-Connecting-IP",
			set:    map[string]string{"CF-Connecting-IP": "2001:db8::1"},
			want:   "2001:db8::1",
		},
		{
			name:   "garbage header value falls back to socket",
			header: "CF-Connecting-IP",
			set:    map[string]string{"CF-Connecting-IP": "not-an-ip"},
			want:   socketIP,
		},
		{
			name:   "missing trusted header falls back to socket",
			header: "CF-Connecting-IP",
			set:    nil,
			want:   socketIP,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			setRealIPHeader(t, tc.header)
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.RemoteAddr = socketIP + ":54321"
			for k, v := range tc.set {
				r.Header.Set(k, v)
			}
			if got := remoteIP(r); got != tc.want {
				t.Fatalf("remoteIP() = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestFailLimitIsPerClientBehindProxy proves the fix: with a trusted header,
// one client exhausting its failed-unwrap budget does not lock out another.
func TestFailLimitIsPerClientBehindProxy(t *testing.T) {
	setRealIPHeader(t, "X-Real-Client")
	e := newEnv(t, Config{})
	fake := "ss." + strings.Repeat("A", 43)

	unwrap := func(clientIP string) int {
		req, _ := http.NewRequest("POST", e.srv.URL+"/v1/unwrap", nil)
		req.Header.Set(TokenHeader, fake)
		req.Header.Set("X-Real-Client", clientIP)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}

	// Client A burns through its failed-unwrap budget until it is rate limited.
	var code int
	for range 10 {
		code = unwrap("198.51.100.1")
		if code == http.StatusTooManyRequests {
			break
		}
	}
	if code != http.StatusTooManyRequests {
		t.Fatalf("client A never rate-limited, last code %d", code)
	}

	// Client B, a different IP, must still be served (404 for the fake token),
	// not collateral-damaged by A's lockout.
	if code := unwrap("198.51.100.2"); code == http.StatusTooManyRequests {
		t.Fatalf("client B was locked out by client A's failures (got 429)")
	}
}
