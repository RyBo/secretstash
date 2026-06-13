// Package store is secretstash's in-memory secret store: burn-after-N-reads,
// TTL expiry, and tamper-evident tombstones. Nothing ever touches disk.
package store

import (
	"bytes"
	"errors"
	"sync"
	"time"

	"github.com/rybo/secretstash/internal/crypto"
)

// Tombstone reasons.
const (
	ReasonConsumed = "consumed"
	ReasonExpired  = "expired"
	ReasonRevoked  = "revoked"
)

var (
	ErrFull = errors.New("store is full")
)

// GoneError reports that a secret existed but is no longer available: the
// tamper-evident signal. At carries the burn/expiry/revocation time.
type GoneError struct {
	Reason string
	At     time.Time
}

func (e *GoneError) Error() string { return "secret " + e.Reason }

// Entry is one sealed secret plus its lifecycle state.
type Entry struct {
	Sealed         crypto.Sealed
	CreatedAt      time.Time
	ExpiresAt      time.Time
	ReadsRemaining int
	ReadsTotal     int
}

type tombstone struct {
	reason    string
	at        time.Time // when it burned/expired/was revoked
	expiresAt time.Time // when the tombstone itself is purged
}

// Limits bounds memory consumption. Zero values are replaced by defaults.
type Limits struct {
	MaxSecrets    int // max live entries (default 10000)
	MaxTombstones int // max tombstones (default 4 * MaxSecrets)
}

func (l Limits) withDefaults() Limits {
	if l.MaxSecrets <= 0 {
		l.MaxSecrets = 10000
	}
	if l.MaxTombstones <= 0 {
		l.MaxTombstones = 4 * l.MaxSecrets
	}
	return l
}

// Store is safe for concurrent use. A plain Mutex (not RWMutex/sync.Map) is
// deliberate: every read path mutates state (decrements reads, burns).
type Store struct {
	mu      sync.Mutex
	entries map[string]*Entry
	tombs   map[string]tombstone
	limits  Limits
	now     func() time.Time
}

func New(limits Limits) *Store {
	return &Store{
		entries: make(map[string]*Entry),
		tombs:   make(map[string]tombstone),
		limits:  limits.withDefaults(),
		now:     time.Now,
	}
}

// Put stores a sealed secret. Returns ErrFull at the MaxSecrets cap.
func (s *Store) Put(sealed *crypto.Sealed, ttl time.Duration, reads int) (*Entry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.entries) >= s.limits.MaxSecrets {
		return nil, ErrFull
	}
	now := s.now()
	e := &Entry{
		Sealed:         *sealed,
		CreatedAt:      now,
		ExpiresAt:      now.Add(ttl),
		ReadsRemaining: reads,
		ReadsTotal:     reads,
	}
	s.entries[sealed.LookupID] = e
	return e, nil
}

// Take consumes one read. Lookup, expiry check, decrement, and burn all
// happen under one lock, so with reads=1 and N concurrent callers exactly
// one receives the entry. The returned Entry is a copy; decryption happens
// outside the lock. Errors: nil,nil = never existed; *GoneError = tamper
// evidence.
func (s *Store) Take(lookupID string) (*Entry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	e, err := s.liveLocked(lookupID)
	if e == nil || err != nil {
		return nil, err
	}

	e.ReadsRemaining--
	cp := *e
	if e.ReadsRemaining <= 0 {
		// The copy shares the ciphertext backing array; clone it before
		// wiping the store's slice or the caller gets zeroed bytes.
		cp.Sealed.Ciphertext = bytes.Clone(e.Sealed.Ciphertext)
		delete(s.entries, lookupID)
		s.tombLocked(lookupID, ReasonConsumed, e.ExpiresAt)
		crypto.Wipe(e.Sealed.Ciphertext)
	}
	return &cp, nil
}

// Peek returns entry metadata without consuming a read.
func (s *Store) Peek(lookupID string) (*Entry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	e, err := s.liveLocked(lookupID)
	if e == nil || err != nil {
		return nil, err
	}
	cp := *e
	return &cp, nil
}

// Revoke deletes a secret, leaving a "revoked" tombstone. It reports
// whether a live entry was revoked; (false, nil) means the ID was never
// seen, and a *GoneError carries the tamper evidence for already-gone IDs.
func (s *Store) Revoke(lookupID string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	e, err := s.liveLocked(lookupID)
	if err != nil {
		return false, err
	}
	if e == nil {
		return false, nil
	}
	delete(s.entries, lookupID)
	s.tombLocked(lookupID, ReasonRevoked, e.ExpiresAt)
	crypto.Wipe(e.Sealed.Ciphertext)
	return true, nil
}

// Len returns the current live entry count.
func (s *Store) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.entries)
}

// Stats returns the current live entry and tombstone counts. Both are sampled
// under one lock so they are mutually consistent.
func (s *Store) Stats() (live, tombstones int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.entries), len(s.tombs)
}

// liveLocked resolves lookupID to a live entry, applying lazy expiry. It
// returns (nil, nil) when the ID was never seen, (nil, *GoneError) when a
// tombstone records its fate, or the live entry. Caller must hold s.mu.
func (s *Store) liveLocked(lookupID string) (*Entry, error) {
	now := s.now()
	if e, ok := s.entries[lookupID]; ok {
		if now.Before(e.ExpiresAt) {
			return e, nil
		}
		// Lazy expiry: correctness never depends on janitor timing.
		delete(s.entries, lookupID)
		s.tombLocked(lookupID, ReasonExpired, e.ExpiresAt)
		crypto.Wipe(e.Sealed.Ciphertext)
	}
	if t, ok := s.tombs[lookupID]; ok {
		if now.Before(t.expiresAt) {
			return nil, &GoneError{Reason: t.reason, At: t.at}
		}
		delete(s.tombs, lookupID)
	}
	return nil, nil
}

// tombLocked records a tombstone living until the original TTL deadline,
// with a floor of 24h so tamper evidence survives short TTLs. Caller must
// hold s.mu.
func (s *Store) tombLocked(lookupID, reason string, originalExpiry time.Time) {
	if len(s.tombs) >= s.limits.MaxTombstones {
		return // cap reached; drop evidence rather than memory
	}
	now := s.now()
	expires := originalExpiry
	if min := now.Add(24 * time.Hour); expires.Before(min) {
		expires = min
	}
	var at time.Time
	if reason == ReasonExpired {
		at = originalExpiry
	} else {
		at = now
	}
	s.tombs[lookupID] = tombstone{reason: reason, at: at, expiresAt: expires}
}

// purge removes expired entries and tombstones; called by the janitor.
func (s *Store) purge() {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.now()
	for id, e := range s.entries {
		if !now.Before(e.ExpiresAt) {
			delete(s.entries, id)
			s.tombLocked(id, ReasonExpired, e.ExpiresAt)
			crypto.Wipe(e.Sealed.Ciphertext)
		}
	}
	for id, t := range s.tombs {
		if !now.Before(t.expiresAt) {
			delete(s.tombs, id)
		}
	}
}
