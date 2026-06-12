package store

import (
	"context"
	"time"
)

// Janitor purges expired entries and tombstones every interval until ctx is
// cancelled. Lazy expiry in liveLocked keeps the store correct regardless;
// the janitor only reclaims memory for never-touched entries.
func (s *Store) Janitor(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.purge()
		}
	}
}
