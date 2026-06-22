package shamir

import (
	"bytes"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
)

func TestSplitCombineRoundTrip(t *testing.T) {
	cases := []struct{ n, k, secretLen int }{
		{2, 2, 1},
		{3, 2, 16},
		{5, 3, 32}, // the real wrap-token size
		{10, 7, 32},
		{255, 128, 8},
	}
	for _, c := range cases {
		secret := randBytes(t, c.secretLen)
		shares, err := Split(secret, c.n, c.k)
		if err != nil {
			t.Fatalf("Split(%d,%d): %v", c.n, c.k, err)
		}
		if len(shares) != c.n {
			t.Fatalf("got %d shares, want %d", len(shares), c.n)
		}
		got, err := Combine(shares)
		if err != nil {
			t.Fatalf("Combine: %v", err)
		}
		if !bytes.Equal(got, secret) {
			t.Fatalf("round trip mismatch for n=%d k=%d", c.n, c.k)
		}
	}
}

func TestAnyKSubsetReconstructs(t *testing.T) {
	secret := randBytes(t, 32)
	const n, k = 5, 3
	shares, err := Split(secret, n, k)
	if err != nil {
		t.Fatal(err)
	}
	for _, combo := range combinations(n, k) {
		subset := make([]string, k)
		for i, idx := range combo {
			subset[i] = shares[idx]
		}
		got, err := Combine(subset)
		if err != nil {
			t.Fatalf("subset %v: %v", combo, err)
		}
		if !bytes.Equal(got, secret) {
			t.Fatalf("subset %v reconstructed the wrong secret", combo)
		}
	}
}

// TestKMinusOneDoesNotRecover demonstrates the threshold operationally: with
// only k-1 real shares, the missing share fully controls the output, so pairing
// them with arbitrary forged shares never reproduces the secret. (True
// information-theoretic secrecy is a mathematical property, not directly
// testable.)
func TestKMinusOneDoesNotRecover(t *testing.T) {
	secret := randBytes(t, 32)
	shares, err := Split(secret, 5, 3)
	if err != nil {
		t.Fatal(err)
	}
	real := []string{shares[0], shares[1]} // k-1 = 2 real shares
	for trial := 0; trial < 64; trial++ {
		forged := encodeShare(3, 200, randBytes(t, 32)) // distinct x, valid checksum
		got, err := Combine(append(append([]string{}, real...), forged))
		if err != nil {
			t.Fatalf("trial %d: %v", trial, err)
		}
		if bytes.Equal(got, secret) {
			t.Fatal("k-1 real shares plus a forged share recovered the secret")
		}
	}
}

func TestSplitInvalidParams(t *testing.T) {
	cases := []struct {
		name    string
		secret  []byte
		n, k    int
		wantErr error
	}{
		{"empty secret", nil, 5, 3, ErrEmptySecret},
		{"threshold 1", []byte("x"), 5, 1, ErrInvalidThreshold},
		{"k greater than n", []byte("x"), 3, 4, ErrInvalidThreshold},
		{"too many shares", []byte("x"), 256, 2, ErrTooManyShares},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := Split(c.secret, c.n, c.k); !errors.Is(err, c.wantErr) {
				t.Fatalf("got %v, want %v", err, c.wantErr)
			}
		})
	}
}

func TestCombineInvalidParams(t *testing.T) {
	secret := randBytes(t, 32)
	shares, err := Split(secret, 5, 3)
	if err != nil {
		t.Fatal(err)
	}
	other, err := Split(secret, 5, 4) // different threshold
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name    string
		shares  []string
		wantErr error
	}{
		{"single share", shares[:1], ErrTooFewShares},
		{"too few for threshold", shares[:2], ErrTooFewShares},
		{"duplicate coordinate", []string{shares[0], shares[0]}, ErrDuplicateX},
		{"threshold mismatch", []string{shares[0], other[1]}, ErrThresholdMismatch},
		{"malformed share", []string{"garbage", shares[1]}, ErrBadShare},
		{"failed checksum", []string{tamperBody(shares[0]), shares[1]}, ErrShareChecksum},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := Combine(c.shares); !errors.Is(err, c.wantErr) {
				t.Fatalf("got %v, want %v", err, c.wantErr)
			}
		})
	}
}

func TestEncodeDecodeShare(t *testing.T) {
	body := randBytes(t, 32)
	s := encodeShare(3, 7, body)
	if !strings.HasPrefix(s, "sss1.3.7.") {
		t.Fatalf("unexpected encoding: %q", s)
	}
	k, x, gotBody, err := decodeShare(s)
	if err != nil {
		t.Fatal(err)
	}
	if k != 3 || x != 7 || !bytes.Equal(gotBody, body) {
		t.Fatalf("decode mismatch: k=%d x=%d body=%x", k, x, gotBody)
	}

	bad := []string{
		"ss.3.7.AAAA.AAAA",            // wrong prefix
		"sss1.3.7.AAAA",               // too few fields
		"sss1.x.7.AAAA.AAAA",          // non-numeric k
		"sss1.3.x.AAAA.AAAA",          // non-numeric x
		"sss1.3.0." + tail(s),         // x out of range (0)
		"sss1.1.7." + tail(s),         // threshold below 2
		"sss1.3.7.!!!!." + bodyOf(s),  // invalid base64 checksum
		"sss1.3.7." + chkOf(s) + ".!", // invalid base64 body
	}
	for _, b := range bad {
		if _, _, _, err := decodeShare(b); err == nil {
			t.Fatalf("decodeShare(%q) accepted a malformed share", b)
		}
	}
}

// TestCombineFixedVector pins a known share set so the JavaScript implementation
// (internal/web/static/shamir.test.mjs) can assert byte-for-byte interoperability
// with the Go encoding. If this vector changes, update the JS test to match.
func TestCombineFixedVector(t *testing.T) {
	const wantSecret = "0123456789abcdef0123456789abcdef"
	shares := []string{
		"sss1.3.1.FGUNgA.kpGnNgOFuHoiusJeocz3Zifs6k1MPqVgi8EPlCtA6jg",
		"sss1.3.3.fcHiSg.-P3y1aaZ0hREMHWEiWs_CtyvNl5EZc4NI8PHtOYs_Bk",
		"sss1.3.5.ZRqVhw.kpWGYlM6w1u93zJPGwSNFbPPjvqRpzCbuUzUpcUIijg",
	}
	got, err := Combine(shares)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != wantSecret {
		t.Fatalf("fixed vector reconstructed %q, want %q", got, wantSecret)
	}
}

func TestRandomnessVariesShares(t *testing.T) {
	secret := randBytes(t, 32)
	a, err := Split(secret, 3, 2)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Split(secret, 3, 2)
	if err != nil {
		t.Fatal(err)
	}
	if a[0] == b[0] {
		t.Fatal("two independent splits produced identical shares")
	}
	for _, shares := range [][]string{a, b} {
		got, err := Combine(shares)
		if err != nil || !bytes.Equal(got, secret) {
			t.Fatalf("split did not round-trip: %v", err)
		}
	}
}

// --- helpers ---

func randBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

// combinations returns every k-sized subset of indices [0,n).
func combinations(n, k int) [][]int {
	var res [][]int
	var rec func(start int, cur []int)
	rec = func(start int, cur []int) {
		if len(cur) == k {
			res = append(res, append([]int(nil), cur...))
			return
		}
		for i := start; i < n; i++ {
			rec(i+1, append(cur, i))
		}
	}
	rec(0, nil)
	return res
}

// tamperBody flips a body byte while keeping the stale checksum, so the share
// fails integrity validation.
func tamperBody(share string) string {
	parts := strings.Split(strings.TrimPrefix(share, sharePrefix), ".")
	body, _ := shareEncoder.DecodeString(parts[3])
	body[0] ^= 0xFF
	parts[3] = shareEncoder.EncodeToString(body)
	return sharePrefix + strings.Join(parts, ".")
}

func parts(share string) []string {
	return strings.Split(strings.TrimPrefix(share, sharePrefix), ".")
}
func chkOf(share string) string  { return parts(share)[2] }
func bodyOf(share string) string { return parts(share)[3] }
func tail(share string) string   { p := parts(share); return p[2] + "." + p[3] }
