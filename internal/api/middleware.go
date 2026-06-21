package api

import (
	"net"
	"net/http"
	"strings"
)

// RealIPHeader, when non-empty, names a header set by a trusted reverse proxy
// that carries the real client IP (e.g. "CF-Connecting-IP", "X-Real-IP"). Set
// once at startup before the server starts serving. Only safe when the origin
// is reachable ONLY through that proxy, so clients cannot supply the header
// themselves.
var RealIPHeader string

// Recover turns handler panics into a bare 500 with no stack leakage.
func Recover(log interface{ Error(string, ...any) }) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if v := recover(); v != nil {
					log.Error("panic", "value", v, "path", r.URL.Path)
					http.Error(w, `{"code":"internal","message":"internal server error"}`, http.StatusInternalServerError)
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}

// SecurityHeaders sets baseline hardening headers on every response.
// hsts should be true when serving TLS.
func SecurityHeaders(hsts bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h := w.Header()
			h.Set("X-Content-Type-Options", "nosniff")
			h.Set("Referrer-Policy", "no-referrer")
			h.Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'")
			h.Set("X-Frame-Options", "DENY")
			if hsts {
				h.Set("Strict-Transport-Security", "max-age=31536000")
			}
			next.ServeHTTP(w, r)
		})
	}
}

// noStore forbids caching of API responses anywhere along the path.
func noStore(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

// maxBytes caps request bodies at the secret limit plus JSON envelope room.
func (a *API) maxBytes(next http.Handler) http.Handler {
	limit := int64(a.cfg.MaxSecretSize) + 4096
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, limit)
		}
		next.ServeHTTP(w, r)
	})
}

// rateLimit applies the per-IP bucket to all /v1/ traffic.
func (a *API) rateLimit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := remoteIP(r)
		if !a.limiter.allow(ip) || !a.failLim.peekOK(ip) {
			a.metrics.recordRateLimited()
			w.Header().Set("Retry-After", "10")
			writeError(w, http.StatusTooManyRequests, "rate_limited", "too many requests")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// remoteIP returns the caller's IP. When RealIPHeader is configured it reads
// the client IP from that proxy-set header; otherwise it uses the socket
// address.
func remoteIP(r *http.Request) string {
	if RealIPHeader != "" {
		if v := r.Header.Get(RealIPHeader); v != "" {
			// Rightmost token: for a list header (X-Forwarded-For) the nearest
			// trusted proxy appends the client last, so a client-supplied first
			// hop cannot be spoofed in; for a single-value header
			// (CF-Connecting-IP) this is just the value.
			if i := strings.LastIndex(v, ","); i >= 0 {
				v = v[i+1:]
			}
			if ip := net.ParseIP(strings.TrimSpace(v)); ip != nil {
				return ip.String()
			}
		}
		// Header missing or unparseable: fall through to the socket address
		// rather than trusting garbage (fails closed to the proxy/tunnel IP).
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
