package api

import (
	"sync"
	"time"
)

// rateLimiter is a per-IP token bucket: refill-on-access, lazily swept.
type rateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
	rate    float64 // tokens per second
	burst   float64
	now     func() time.Time
	lastGC  time.Time
}

type bucket struct {
	tokens float64
	last   time.Time
}

func newRateLimiter(rate, burst float64) *rateLimiter {
	return &rateLimiter{
		buckets: make(map[string]*bucket),
		rate:    rate,
		burst:   burst,
		now:     time.Now,
	}
}

// allow consumes one token for key, reporting whether the request may pass.
func (l *rateLimiter) allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.refillLocked(key)
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// take consumes a token without gating — used to charge a budget after the
// fact (e.g. failed unwrap attempts), letting the balance go negative.
func (l *rateLimiter) take(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.refillLocked(key).tokens--
}

// peekOK reports whether key has budget left, without consuming.
func (l *rateLimiter) peekOK(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.refillLocked(key).tokens >= 0
}

func (l *rateLimiter) refillLocked(key string) *bucket {
	now := l.now()
	l.gcLocked(now)
	b, ok := l.buckets[key]
	if !ok {
		b = &bucket{tokens: l.burst, last: now}
		l.buckets[key] = b
		return b
	}
	b.tokens += now.Sub(b.last).Seconds() * l.rate
	if b.tokens > l.burst {
		b.tokens = l.burst
	}
	b.last = now
	return b
}

// gcLocked sweeps buckets that have fully refilled (i.e. idle IPs) at most
// once a minute, bounding memory across many client IPs.
func (l *rateLimiter) gcLocked(now time.Time) {
	if now.Sub(l.lastGC) < time.Minute {
		return
	}
	l.lastGC = now
	for k, b := range l.buckets {
		idle := now.Sub(b.last).Seconds() * l.rate
		if b.tokens+idle >= l.burst {
			delete(l.buckets, k)
		}
	}
}
