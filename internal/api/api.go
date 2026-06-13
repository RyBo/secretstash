// Package api implements the secretstash REST API.
package api

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/rybo/secretstash/internal/crypto"
	"github.com/rybo/secretstash/internal/store"
	"github.com/rybo/secretstash/internal/version"
)

// TokenHeader carries the wrap token. Header, never URL: URLs leak into
// server/proxy logs and browser history.
const TokenHeader = "X-Stash-Token"

// Config bounds what clients may request. Zero values get defaults.
type Config struct {
	DefaultTTL    time.Duration // default 24h
	MaxTTL        time.Duration // default 168h
	MinTTL        time.Duration // default 10s
	MaxReads      int           // default 100
	MaxSecretSize int           // plaintext bytes, default 64 KiB
	ShareBaseURL  string        // external base URL for share links
}

func (c Config) withDefaults() Config {
	if c.DefaultTTL <= 0 {
		c.DefaultTTL = 24 * time.Hour
	}
	if c.MaxTTL <= 0 {
		c.MaxTTL = 168 * time.Hour
	}
	if c.MinTTL <= 0 {
		c.MinTTL = 10 * time.Second
	}
	if c.MaxReads <= 0 {
		c.MaxReads = 100
	}
	if c.MaxSecretSize <= 0 {
		c.MaxSecretSize = 64 * 1024
	}
	return c
}

type API struct {
	store   *store.Store
	cfg     Config
	log     *slog.Logger
	started time.Time
	limiter *rateLimiter
	failLim *rateLimiter
	metrics *metrics
}

func New(st *store.Store, cfg Config, logger *slog.Logger) *API {
	if logger == nil {
		logger = slog.Default()
	}
	return &API{
		store:   st,
		cfg:     cfg.withDefaults(),
		log:     logger,
		started: time.Now(),
		// 10 req/s burst 20 per IP across /v1/.
		limiter: newRateLimiter(10, 20),
		// Stricter budget for failed unwraps: ~5/min.
		failLim: newRateLimiter(5.0/60.0, 5),
		metrics: newMetrics(),
	}
}

// Routes returns the /v1/ handler with the API middleware chain applied.
func (a *API) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/wrap", a.handleWrap)
	mux.HandleFunc("POST /v1/unwrap", a.handleUnwrap)
	mux.HandleFunc("GET /v1/peek", a.handlePeek)
	mux.HandleFunc("DELETE /v1/secret", a.handleRevoke)
	mux.HandleFunc("GET /v1/sys/health", a.handleHealth)

	var h http.Handler = mux
	h = a.rateLimit(h)
	h = a.maxBytes(h)
	h = noStore(h)
	return h
}

// --- request/response shapes ---

type wrapRequest struct {
	Secret string `json:"secret"`
	TTL    string `json:"ttl,omitempty"`
	Reads  int    `json:"reads,omitempty"`
}

type wrapResponse struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
	Reads     int       `json:"reads"`
	ShareURL  string    `json:"share_url,omitempty"`
}

type unwrapResponse struct {
	Secret         string    `json:"secret"`
	ReadsRemaining int       `json:"reads_remaining"`
	CreatedAt      time.Time `json:"created_at"`
}

type peekResponse struct {
	Exists         bool      `json:"exists"`
	ExpiresAt      time.Time `json:"expires_at"`
	ReadsRemaining int       `json:"reads_remaining"`
}

type healthResponse struct {
	Status        string `json:"status"`
	Version       string `json:"version"`
	UptimeSeconds int64  `json:"uptime_seconds"`
}

type apiError struct {
	Code       string     `json:"code"`
	Message    string     `json:"message"`
	ConsumedAt *time.Time `json:"consumed_at,omitempty"`
}

// --- handlers ---

func (a *API) handleWrap(w http.ResponseWriter, r *http.Request) {
	var req wrapRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "invalid JSON body")
		return
	}
	if req.Secret == "" {
		writeError(w, http.StatusBadRequest, "bad_request", "secret must not be empty")
		return
	}
	if len(req.Secret) > a.cfg.MaxSecretSize {
		writeError(w, http.StatusRequestEntityTooLarge, "too_large", "secret exceeds maximum size")
		return
	}

	ttl := a.cfg.DefaultTTL
	if req.TTL != "" {
		d, err := time.ParseDuration(req.TTL)
		if err != nil {
			writeError(w, http.StatusBadRequest, "bad_request", "ttl must be a duration like 30m or 24h")
			return
		}
		// Reject, don't clamp: silent clamping surprises security tools.
		if d < a.cfg.MinTTL || d > a.cfg.MaxTTL {
			writeError(w, http.StatusBadRequest, "bad_request",
				"ttl out of range ("+a.cfg.MinTTL.String()+" to "+a.cfg.MaxTTL.String()+")")
			return
		}
		ttl = d
	}

	reads := 1
	if req.Reads != 0 {
		if req.Reads < 1 || req.Reads > a.cfg.MaxReads {
			writeError(w, http.StatusBadRequest, "bad_request", "reads out of range")
			return
		}
		reads = req.Reads
	}

	token, raw, err := crypto.NewToken()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "token generation failed")
		return
	}
	plaintext := []byte(req.Secret)
	sealed, err := crypto.Seal(raw, plaintext)
	crypto.Wipe(plaintext)
	crypto.Wipe(raw)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "encryption failed")
		return
	}

	entry, err := a.store.Put(sealed, ttl, reads)
	if err != nil {
		if errors.Is(err, store.ErrFull) {
			a.metrics.recordStoreFull()
			writeError(w, http.StatusInsufficientStorage, "store_full", "server secret store is full")
			return
		}
		writeError(w, http.StatusInternalServerError, "internal", "store failure")
		return
	}

	a.audit("wrap", r, sealed.LookupID, "reads", reads, "ttl", ttl.String())

	resp := wrapResponse{Token: token, ExpiresAt: entry.ExpiresAt.UTC(), Reads: reads}
	if a.cfg.ShareBaseURL != "" {
		// Token in the URL fragment: never sent to any server.
		resp.ShareURL = a.cfg.ShareBaseURL + "/s#" + token
	}
	writeJSON(w, http.StatusOK, resp)
}

func (a *API) handleUnwrap(w http.ResponseWriter, r *http.Request) {
	raw, id, ok := a.tokenFrom(w, r)
	if !ok {
		return
	}
	defer crypto.Wipe(raw)

	entry, err := a.store.Take(id)
	if err != nil || entry == nil {
		a.writeGone(w, r, id, err)
		return
	}

	plaintext, err := crypto.Open(raw, &entry.Sealed)
	if err != nil {
		// Token hashed to the right slot but failed GCM auth: the stored
		// ciphertext was tampered with. Loud server-side signal.
		a.metrics.recordFailure("tamper")
		a.log.Warn("audit", "event", "unwrap_failed", "reason", "tamper",
			"id_prefix", idPrefix(id), "remote", remoteIP(r))
		writeError(w, http.StatusInternalServerError, "internal", "decryption failed")
		return
	}

	a.audit("unwrap", r, id, "reads_remaining", entry.ReadsRemaining)
	writeJSON(w, http.StatusOK, unwrapResponse{
		Secret:         string(plaintext),
		ReadsRemaining: entry.ReadsRemaining,
		CreatedAt:      entry.CreatedAt.UTC(),
	})
	crypto.Wipe(plaintext)
}

func (a *API) handlePeek(w http.ResponseWriter, r *http.Request) {
	raw, id, ok := a.tokenFrom(w, r)
	if !ok {
		return
	}
	crypto.Wipe(raw)

	entry, err := a.store.Peek(id)
	if err != nil || entry == nil {
		a.writeGone(w, r, id, err)
		return
	}
	a.metrics.recordPeek()
	writeJSON(w, http.StatusOK, peekResponse{
		Exists:         true,
		ExpiresAt:      entry.ExpiresAt.UTC(),
		ReadsRemaining: entry.ReadsRemaining,
	})
}

func (a *API) handleRevoke(w http.ResponseWriter, r *http.Request) {
	raw, id, ok := a.tokenFrom(w, r)
	if !ok {
		return
	}
	crypto.Wipe(raw)

	revoked, err := a.store.Revoke(id)
	if err != nil || !revoked {
		a.writeGone(w, r, id, err)
		return
	}
	a.audit("revoke", r, id)
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, healthResponse{
		Status:        "ok",
		Version:       version.Version,
		UptimeSeconds: int64(time.Since(a.started).Seconds()),
	})
}

// --- helpers ---

// tokenFrom parses the X-Stash-Token header; on failure it writes the error
// response (consuming a failed-unwrap rate-limit token) and returns ok=false.
func (a *API) tokenFrom(w http.ResponseWriter, r *http.Request) (raw []byte, id string, ok bool) {
	token := r.Header.Get(TokenHeader)
	if token == "" {
		writeError(w, http.StatusBadRequest, "bad_request", "missing "+TokenHeader+" header")
		return nil, "", false
	}
	raw, err := crypto.ParseToken(token)
	if err != nil {
		a.failedAuth(w, r, "auth_fail", "")
		// Same response as a never-issued token: no format oracle.
		writeError(w, http.StatusNotFound, "not_found", "no secret found for this token")
		return nil, "", false
	}
	return raw, crypto.LookupID(raw), true
}

// writeGone maps store miss results to 404/410 with tamper evidence, and
// charges the stricter failed-unwrap rate limit.
func (a *API) writeGone(w http.ResponseWriter, r *http.Request, id string, err error) {
	var gone *store.GoneError
	if errors.As(err, &gone) {
		a.failedAuth(w, r, gone.Reason, id)
		at := gone.At.UTC()
		e := apiError{Code: gone.Reason}
		switch gone.Reason {
		case store.ReasonConsumed:
			e.Message = "secret already consumed; its final read occurred at " + at.Format(time.RFC3339)
			e.ConsumedAt = &at
		case store.ReasonExpired:
			e.Message = "secret expired at " + at.Format(time.RFC3339)
		case store.ReasonRevoked:
			e.Message = "secret was revoked at " + at.Format(time.RFC3339)
		}
		writeJSONError(w, http.StatusGone, e)
		return
	}
	a.failedAuth(w, r, "unknown", id)
	writeError(w, http.StatusNotFound, "not_found", "no secret found for this token")
}

// failedAuth logs a failed unwrap attempt and burns a failed-attempt
// rate-limit token for the caller's IP. A failure against a consumed secret
// is the operator-side tamper alarm, hence WARN.
func (a *API) failedAuth(w http.ResponseWriter, r *http.Request, reason, id string) {
	a.metrics.recordFailure(reason)
	a.failLim.take(remoteIP(r))
	level := slog.LevelInfo
	if reason == store.ReasonConsumed {
		level = slog.LevelWarn
	}
	a.log.Log(r.Context(), level, "audit", "event", "unwrap_failed",
		"reason", reason, "id_prefix", idPrefix(id), "remote", remoteIP(r))
}

func (a *API) audit(event string, r *http.Request, id string, kv ...any) {
	a.metrics.recordEvent(event)
	args := append([]any{"event", event, "id_prefix", idPrefix(id), "remote", remoteIP(r)}, kv...)
	a.log.Info("audit", args...)
}

// HandleMetrics serves the Prometheus text exposition. It is registered
// outside Routes() so scrapers are not subject to the per-IP rate limiter,
// and is meant to be restricted at the network level (it is unauthenticated).
func (a *API) HandleMetrics(w http.ResponseWriter, r *http.Request) {
	live, tombs := a.store.Stats()
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	a.metrics.writeProm(w, live, tombs, time.Since(a.started), version.Version)
}

func idPrefix(id string) string {
	if len(id) < 8 {
		return id
	}
	return id[:8]
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, code, msg string) {
	writeJSONError(w, status, apiError{Code: code, Message: msg})
}

func writeJSONError(w http.ResponseWriter, status int, e apiError) {
	writeJSON(w, status, e)
}
