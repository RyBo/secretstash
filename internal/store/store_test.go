package store

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/rybo/secretstash/internal/crypto"
)

func newSealed(t *testing.T) (*crypto.Sealed, []byte) {
	t.Helper()
	_, raw, err := crypto.NewToken()
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := crypto.Seal(raw, []byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	return sealed, raw
}

// fakeClock lets tests control time.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func newTestStore(limits Limits) (*Store, *fakeClock) {
	s := New(limits)
	clk := &fakeClock{t: time.Date(2026, 6, 12, 12, 0, 0, 0, time.UTC)}
	s.now = clk.now
	return s, clk
}

func TestTakeBurnsAfterReads(t *testing.T) {
	s, _ := newTestStore(Limits{})
	sealed, _ := newSealed(t)
	if _, err := s.Put(sealed, time.Hour, 2); err != nil {
		t.Fatal(err)
	}

	e1, err := s.Take(sealed.LookupID)
	if err != nil || e1 == nil {
		t.Fatalf("first take: %v %v", e1, err)
	}
	if e1.ReadsRemaining != 1 {
		t.Fatalf("want 1 read remaining, got %d", e1.ReadsRemaining)
	}

	e2, err := s.Take(sealed.LookupID)
	if err != nil || e2 == nil {
		t.Fatalf("second take: %v %v", e2, err)
	}
	if e2.ReadsRemaining != 0 {
		t.Fatalf("want 0 reads remaining, got %d", e2.ReadsRemaining)
	}

	_, err = s.Take(sealed.LookupID)
	var gone *GoneError
	if !errors.As(err, &gone) || gone.Reason != ReasonConsumed {
		t.Fatalf("third take: want consumed GoneError, got %v", err)
	}
	if gone.At.IsZero() {
		t.Fatal("tombstone missing consumed-at time")
	}
}

func TestConcurrentTakeExactlyOneWinner(t *testing.T) {
	s, _ := newTestStore(Limits{})
	sealed, _ := newSealed(t)
	if _, err := s.Put(sealed, time.Hour, 1); err != nil {
		t.Fatal(err)
	}

	const n = 100
	var wg sync.WaitGroup
	results := make([]error, n)
	wins := make([]bool, n)
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			e, err := s.Take(sealed.LookupID)
			results[i] = err
			wins[i] = e != nil && err == nil
		}()
	}
	wg.Wait()

	winners, consumed := 0, 0
	for i := range n {
		if wins[i] {
			winners++
			continue
		}
		var gone *GoneError
		if errors.As(results[i], &gone) && gone.Reason == ReasonConsumed {
			consumed++
		}
	}
	if winners != 1 {
		t.Fatalf("want exactly 1 winner, got %d", winners)
	}
	if consumed != n-1 {
		t.Fatalf("want %d consumed errors, got %d", n-1, consumed)
	}
}

func TestTTLExpiry(t *testing.T) {
	s, clk := newTestStore(Limits{})
	sealed, _ := newSealed(t)
	if _, err := s.Put(sealed, time.Minute, 1); err != nil {
		t.Fatal(err)
	}

	// Just before the boundary: still live.
	clk.advance(time.Minute - time.Nanosecond)
	if e, err := s.Peek(sealed.LookupID); err != nil || e == nil {
		t.Fatalf("pre-boundary peek: %v %v", e, err)
	}

	// At the boundary: expired (lazy, no janitor running).
	clk.advance(time.Nanosecond)
	_, err := s.Take(sealed.LookupID)
	var gone *GoneError
	if !errors.As(err, &gone) || gone.Reason != ReasonExpired {
		t.Fatalf("want expired GoneError, got %v", err)
	}
}

func TestPeekDoesNotConsume(t *testing.T) {
	s, _ := newTestStore(Limits{})
	sealed, _ := newSealed(t)
	s.Put(sealed, time.Hour, 1)

	for range 5 {
		e, err := s.Peek(sealed.LookupID)
		if err != nil || e == nil || e.ReadsRemaining != 1 {
			t.Fatalf("peek changed state: %+v %v", e, err)
		}
	}
}

func TestStats(t *testing.T) {
	s, _ := newTestStore(Limits{})
	sealed, _ := newSealed(t)
	s.Put(sealed, time.Hour, 1)

	if live, tombs := s.Stats(); live != 1 || tombs != 0 {
		t.Fatalf("after put: live=%d tombs=%d, want 1/0", live, tombs)
	}

	// Consuming the only read leaves a tombstone behind.
	if _, err := s.Take(sealed.LookupID); err != nil {
		t.Fatal(err)
	}
	if live, tombs := s.Stats(); live != 0 || tombs != 1 {
		t.Fatalf("after take: live=%d tombs=%d, want 0/1", live, tombs)
	}
}

func TestRevoke(t *testing.T) {
	s, _ := newTestStore(Limits{})
	sealed, _ := newSealed(t)
	s.Put(sealed, time.Hour, 1)

	ok, err := s.Revoke(sealed.LookupID)
	if !ok || err != nil {
		t.Fatalf("revoke: %v %v", ok, err)
	}

	_, err = s.Take(sealed.LookupID)
	var gone *GoneError
	if !errors.As(err, &gone) || gone.Reason != ReasonRevoked {
		t.Fatalf("want revoked GoneError, got %v", err)
	}

	// Revoking an unknown ID is (false, nil).
	ok, err = s.Revoke("deadbeef")
	if ok || err != nil {
		t.Fatalf("revoke unknown: %v %v", ok, err)
	}
}

func TestUnknownIDIsNilNil(t *testing.T) {
	s, _ := newTestStore(Limits{})
	e, err := s.Take("0000000000000000000000000000000000000000000000000000000000000000")
	if e != nil || err != nil {
		t.Fatalf("want nil,nil for unknown ID, got %v %v", e, err)
	}
}

func TestMaxSecretsCap(t *testing.T) {
	s, _ := newTestStore(Limits{MaxSecrets: 2})
	a, _ := newSealed(t)
	b, _ := newSealed(t)
	c, _ := newSealed(t)
	if _, err := s.Put(a, time.Hour, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Put(b, time.Hour, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Put(c, time.Hour, 1); !errors.Is(err, ErrFull) {
		t.Fatalf("want ErrFull, got %v", err)
	}
}

func TestJanitorPurges(t *testing.T) {
	s, clk := newTestStore(Limits{})
	sealed, _ := newSealed(t)
	s.Put(sealed, time.Minute, 1)

	clk.advance(2 * time.Minute)
	s.purge()
	if s.Len() != 0 {
		t.Fatalf("want 0 live entries after purge, got %d", s.Len())
	}
	// Entry left an expired tombstone…
	if _, err := s.Take(sealed.LookupID); err == nil {
		t.Fatal("want GoneError from tombstone")
	}
	// …which itself is purged after its 24h floor.
	clk.advance(25 * time.Hour)
	s.purge()
	e, err := s.Take(sealed.LookupID)
	if e != nil || err != nil {
		t.Fatalf("want nil,nil after tombstone purge, got %v %v", e, err)
	}
}

func TestTombstoneFloor(t *testing.T) {
	// A 10s TTL secret must leave tamper evidence for >= 24h.
	s, clk := newTestStore(Limits{})
	sealed, _ := newSealed(t)
	s.Put(sealed, 10*time.Second, 1)
	if _, err := s.Take(sealed.LookupID); err != nil {
		t.Fatal(err)
	}

	clk.advance(23 * time.Hour)
	var gone *GoneError
	if _, err := s.Take(sealed.LookupID); !errors.As(err, &gone) {
		t.Fatalf("tombstone gone before 24h floor: %v", err)
	}
}

func TestCiphertextWipedOnBurn(t *testing.T) {
	s, _ := newTestStore(Limits{})
	sealed, _ := newSealed(t)
	// Keep a reference to the same backing array the store holds.
	ct := sealed.Ciphertext
	s.Put(sealed, time.Hour, 1)
	if _, err := s.Take(sealed.LookupID); err != nil {
		t.Fatal(err)
	}
	allZero := true
	for _, b := range ct {
		if b != 0 {
			allZero = false
			break
		}
	}
	if !allZero {
		t.Fatal("ciphertext not wiped after burn")
	}
}

func TestManyEntriesIndependent(t *testing.T) {
	s, _ := newTestStore(Limits{})
	ids := make([]string, 50)
	for i := range ids {
		sealed, _ := newSealed(t)
		if _, err := s.Put(sealed, time.Hour, 1); err != nil {
			t.Fatal(err)
		}
		ids[i] = sealed.LookupID
	}
	for i, id := range ids {
		e, err := s.Take(id)
		if err != nil || e == nil {
			t.Fatalf("entry %d: %v %v", i, e, err)
		}
	}
	if got := s.Len(); got != 0 {
		t.Fatalf("want empty store, got %d", got)
	}
}

func TestTakenCopyDecryptsAfterBurn(t *testing.T) {
	// The entry returned by the final Take must still decrypt even though
	// the store wipes its own ciphertext on burn.
	s, _ := newTestStore(Limits{})
	sealed, raw := newSealed(t)
	s.Put(sealed, time.Hour, 1)

	e, err := s.Take(sealed.LookupID)
	if err != nil || e == nil {
		t.Fatalf("take: %v %v", e, err)
	}
	pt, err := crypto.Open(raw, &e.Sealed)
	if err != nil {
		t.Fatalf("decrypting taken copy: %v", err)
	}
	if string(pt) != "payload" {
		t.Fatalf("got %q", pt)
	}
}
