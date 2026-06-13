package api

import (
	"fmt"
	"io"
	"sort"
	"sync/atomic"
	"time"
)

// failureReasons is the fixed set of unwrap-failure reasons we expose as
// label values. Pre-registering them keeps the map lock-free at runtime and
// bounded: an unexpected reason folds into "unknown" rather than growing it.
var failureReasons = []string{"consumed", "expired", "revoked", "auth_fail", "tamper", "unknown"}

// metrics holds atomic counters for the /metrics endpoint. A nil *metrics is
// not valid; construct with newMetrics. All methods are safe for concurrent
// use and cheap enough to call on every request.
type metrics struct {
	wraps       atomic.Int64
	unwraps     atomic.Int64
	peeks       atomic.Int64
	revokes     atomic.Int64
	storeFull   atomic.Int64
	rateLimited atomic.Int64

	// failures is keyed by the values in failureReasons and never resized
	// after construction, so concurrent reads/writes need no lock.
	failures map[string]*atomic.Int64
}

func newMetrics() *metrics {
	m := &metrics{failures: make(map[string]*atomic.Int64, len(failureReasons))}
	for _, r := range failureReasons {
		m.failures[r] = new(atomic.Int64)
	}
	return m
}

// recordEvent counts a successful audit event. Unknown events are ignored so
// adding new audit calls never silently miscounts.
func (m *metrics) recordEvent(event string) {
	switch event {
	case "wrap":
		m.wraps.Add(1)
	case "unwrap":
		m.unwraps.Add(1)
	case "revoke":
		m.revokes.Add(1)
	}
}

// recordFailure counts a failed unwrap by reason, folding any unregistered
// reason into "unknown".
func (m *metrics) recordFailure(reason string) {
	c, ok := m.failures[reason]
	if !ok {
		c = m.failures["unknown"]
	}
	c.Add(1)
}

func (m *metrics) recordPeek()        { m.peeks.Add(1) }
func (m *metrics) recordStoreFull()   { m.storeFull.Add(1) }
func (m *metrics) recordRateLimited() { m.rateLimited.Add(1) }

// writeProm renders the current metrics in Prometheus text exposition format
// (version 0.0.4). Gauges (live, tombs, uptime) are sampled by the caller at
// scrape time and passed in.
func (m *metrics) writeProm(w io.Writer, live, tombs int, uptime time.Duration, version string) {
	gauge(w, "secretstash_build_info", "Build information; constant 1, version in the label.",
		1, `version=`+quote(version))
	gauge(w, "secretstash_uptime_seconds", "Seconds since the server started.",
		int64(uptime.Seconds()), "")
	gauge(w, "secretstash_live_secrets", "Secrets currently held in the store.",
		int64(live), "")
	gauge(w, "secretstash_tombstones", "Tamper-evident tombstones currently retained.",
		int64(tombs), "")

	counter(w, "secretstash_wraps_total", "Secrets wrapped.", m.wraps.Load(), "")
	counter(w, "secretstash_unwraps_total", "Secrets successfully unwrapped.", m.unwraps.Load(), "")
	counter(w, "secretstash_peeks_total", "Metadata peeks.", m.peeks.Load(), "")
	counter(w, "secretstash_revokes_total", "Secrets revoked before being read.", m.revokes.Load(), "")
	counter(w, "secretstash_store_full_total", "Wraps rejected because the store was full.", m.storeFull.Load(), "")
	counter(w, "secretstash_rate_limited_total", "Requests rejected by the rate limiter.", m.rateLimited.Load(), "")

	// Failed unwraps, one line per reason. Sorted for stable output.
	const name = "secretstash_unwrap_failures_total"
	fmt.Fprintf(w, "# HELP %s Failed unwrap attempts by reason.\n", name)
	fmt.Fprintf(w, "# TYPE %s counter\n", name)
	reasons := make([]string, 0, len(m.failures))
	for r := range m.failures {
		reasons = append(reasons, r)
	}
	sort.Strings(reasons)
	for _, r := range reasons {
		fmt.Fprintf(w, "%s{reason=%s} %d\n", name, quote(r), m.failures[r].Load())
	}
}

func gauge(w io.Writer, name, help string, value int64, label string) {
	writeMetric(w, "gauge", name, help, value, label)
}

func counter(w io.Writer, name, help string, value int64, label string) {
	writeMetric(w, "counter", name, help, value, label)
}

func writeMetric(w io.Writer, typ, name, help string, value int64, label string) {
	fmt.Fprintf(w, "# HELP %s %s\n", name, help)
	fmt.Fprintf(w, "# TYPE %s %s\n", name, typ)
	if label != "" {
		fmt.Fprintf(w, "%s{%s} %d\n", name, label, value)
		return
	}
	fmt.Fprintf(w, "%s %d\n", name, value)
}

// quote renders a Prometheus label value: double-quoted with backslashes,
// double quotes, and newlines escaped per the exposition format.
func quote(s string) string {
	r := make([]byte, 0, len(s)+2)
	r = append(r, '"')
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\\':
			r = append(r, '\\', '\\')
		case '"':
			r = append(r, '\\', '"')
		case '\n':
			r = append(r, '\\', 'n')
		default:
			r = append(r, s[i])
		}
	}
	r = append(r, '"')
	return string(r)
}
