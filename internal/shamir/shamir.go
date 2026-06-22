// Package shamir implements byte-wise Shamir secret sharing over GF(2^8).
//
// It splits an arbitrary secret (in secretstash, the 32-byte wrap token) into
// n shares such that any k reconstruct it and any k-1 reveal nothing. The math
// uses only the standard library: field arithmetic is constant-time (no
// data-dependent branches or table lookups) and randomness comes from
// crypto/rand. There are no external dependencies.
//
// Shares are emitted as self-describing strings:
//
//	sss1.<k>.<x>.<chk>.<base64url(body)>
//
// where k is the threshold, x is the share's evaluation point (1..255), chk is
// a short integrity checksum, and body is the share bytes. Combine validates
// the checksum so a mistyped or corrupted share is rejected with a clear error.
//
// The checksum is NOT a MAC: it is computable by anyone and only guards against
// accidental corruption, not a maliciously crafted share. A deliberately wrong
// share reconstructs a wrong secret; in secretstash that surfaces as an
// AES-GCM authentication failure when the rebuilt token is used to unwrap.
package shamir

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

const (
	sharePrefix  = "sss1." // prefix + format version, like the "ss." token prefix
	shareVersion = 1
	checksumLen  = 4 // bytes of SHA-256 kept as the share checksum
)

var shareEncoder = base64.RawURLEncoding

var (
	ErrEmptySecret       = errors.New("shamir: secret is empty")
	ErrInvalidThreshold  = errors.New("shamir: threshold must satisfy 2 <= k <= n")
	ErrTooManyShares     = errors.New("shamir: number of shares exceeds 255")
	ErrBadShare          = errors.New("shamir: malformed share")
	ErrShareChecksum     = errors.New("shamir: share failed checksum (corrupted or mistyped)")
	ErrThresholdMismatch = errors.New("shamir: shares disagree on threshold")
	ErrShareLength       = errors.New("shamir: shares differ in length")
	ErrDuplicateX        = errors.New("shamir: duplicate share coordinate")
	ErrTooFewShares      = errors.New("shamir: not enough shares to reconstruct")
)

// Split divides secret into n shares, any k of which reconstruct it. It returns
// encoded share strings. Requires 2 <= k <= n <= 255 and a non-empty secret.
func Split(secret []byte, n, k int) ([]string, error) {
	if len(secret) == 0 {
		return nil, ErrEmptySecret
	}
	if k < 2 || k > n {
		return nil, ErrInvalidThreshold
	}
	if n > 255 {
		return nil, ErrTooManyShares
	}

	raw, err := splitRaw(secret, n, k)
	if err != nil {
		return nil, err
	}
	out := make([]string, n)
	for i, s := range raw {
		body, x := s[:len(s)-1], int(s[len(s)-1])
		out[i] = encodeShare(k, x, body)
	}
	return out, nil
}

// Combine validates and reconstructs the secret from k or more encoded shares
// produced by Split. All shares must agree on the threshold and length and
// carry distinct coordinates. Supplying fewer than the original k shares
// returns ErrTooFewShares; a corrupted share returns ErrShareChecksum.
func Combine(shares []string) ([]byte, error) {
	if len(shares) < 2 {
		return nil, ErrTooFewShares
	}

	var wantK, bodyLen int
	seen := make(map[int]bool, len(shares))
	raw := make([][]byte, 0, len(shares))
	for i, s := range shares {
		k, x, body, err := decodeShare(s)
		if err != nil {
			return nil, fmt.Errorf("share %d: %w", i+1, err)
		}
		switch {
		case i == 0:
			wantK, bodyLen = k, len(body)
		case k != wantK:
			return nil, fmt.Errorf("share %d: %w", i+1, ErrThresholdMismatch)
		case len(body) != bodyLen:
			return nil, fmt.Errorf("share %d: %w", i+1, ErrShareLength)
		}
		if seen[x] {
			return nil, fmt.Errorf("share %d: %w", i+1, ErrDuplicateX)
		}
		seen[x] = true

		point := make([]byte, bodyLen+1)
		copy(point, body)
		point[bodyLen] = byte(x)
		raw = append(raw, point)
	}
	if len(raw) < wantK {
		return nil, ErrTooFewShares
	}
	return combineRaw(raw), nil
}

// splitRaw builds the shares as body||x byte slices (x = 1..n).
func splitRaw(secret []byte, n, k int) ([][]byte, error) {
	shares := make([][]byte, n)
	for i := range shares {
		shares[i] = make([]byte, len(secret)+1)
		shares[i][len(secret)] = byte(i + 1) // x-coordinate, never 0
	}

	// Each secret byte gets its own degree k-1 polynomial whose constant term
	// is that byte and whose other coefficients are fresh random field elements.
	coeffs := make([]byte, k)
	for bi, sb := range secret {
		coeffs[0] = sb
		if _, err := rand.Read(coeffs[1:]); err != nil {
			return nil, fmt.Errorf("shamir: reading randomness: %w", err)
		}
		for i := range shares {
			shares[i][bi] = gfEval(coeffs, shares[i][len(secret)])
		}
	}
	return shares, nil
}

// combineRaw reconstructs the secret via Lagrange interpolation at x=0. In
// GF(2^8) subtraction is XOR and negation is the identity, so (0 - xj) = xj and
// (xi - xj) = xi ^ xj.
func combineRaw(shares [][]byte) []byte {
	bodyLen := len(shares[0]) - 1
	xs := make([]byte, len(shares))
	for i, s := range shares {
		xs[i] = s[bodyLen]
	}

	secret := make([]byte, bodyLen)
	for bi := 0; bi < bodyLen; bi++ {
		var acc byte
		for i := range shares {
			num, den := byte(1), byte(1)
			for j := range shares {
				if j == i {
					continue
				}
				num = gfMul(num, xs[j])
				den = gfMul(den, xs[i]^xs[j])
			}
			basis := gfMul(num, gfInv(den))
			acc ^= gfMul(shares[i][bi], basis)
		}
		secret[bi] = acc
	}
	return secret
}

// gfEval evaluates a polynomial (coeffs[0] is the constant term) at x using
// Horner's method in GF(2^8).
func gfEval(coeffs []byte, x byte) byte {
	var y byte
	for i := len(coeffs) - 1; i >= 0; i-- {
		y = gfMul(y, x) ^ coeffs[i]
	}
	return y
}

// gfMul multiplies two GF(2^8) elements (AES field, modulus 0x11b) in constant
// time: the control flow and memory access pattern do not depend on the inputs.
func gfMul(a, b byte) byte {
	var p byte
	for i := 0; i < 8; i++ {
		p ^= a & -(b & 1) // add a into p iff b's low bit is set
		b >>= 1
		hi := -(a >> 7) // 0xFF iff a's high bit is set
		a <<= 1         //
		a ^= 0x1b & hi  // reduce by the modulus when the high bit overflowed
	}
	return p
}

// gfInv returns the multiplicative inverse of a in GF(2^8) as a^254 (the
// multiplicative group has order 255). The exponent is a fixed constant, so the
// loop is constant-time with respect to a. gfInv(0) is 0.
func gfInv(a byte) byte {
	result := byte(1)
	base := a
	for exp := 254; exp > 0; exp >>= 1 {
		if exp&1 == 1 {
			result = gfMul(result, base)
		}
		base = gfMul(base, base)
	}
	return result
}

// encodeShare renders one share as sss1.<k>.<x>.<chk>.<base64url(body)>.
func encodeShare(k, x int, body []byte) string {
	chk := shareChecksum(k, x, body)
	return fmt.Sprintf("%s%d.%d.%s.%s", sharePrefix, k, x,
		shareEncoder.EncodeToString(chk), shareEncoder.EncodeToString(body))
}

// decodeShare parses and integrity-checks one encoded share.
func decodeShare(s string) (k, x int, body []byte, err error) {
	rest, ok := strings.CutPrefix(s, sharePrefix)
	if !ok {
		return 0, 0, nil, ErrBadShare
	}
	parts := strings.Split(rest, ".")
	if len(parts) != 4 {
		return 0, 0, nil, ErrBadShare
	}
	if k, err = strconv.Atoi(parts[0]); err != nil || k < 2 || k > 255 {
		return 0, 0, nil, ErrBadShare
	}
	if x, err = strconv.Atoi(parts[1]); err != nil || x < 1 || x > 255 {
		return 0, 0, nil, ErrBadShare
	}
	chk, err := shareEncoder.DecodeString(parts[2])
	if err != nil || len(chk) != checksumLen {
		return 0, 0, nil, ErrBadShare
	}
	body, err = shareEncoder.DecodeString(parts[3])
	if err != nil || len(body) == 0 {
		return 0, 0, nil, ErrBadShare
	}
	if !bytes.Equal(chk, shareChecksum(k, x, body)) {
		return 0, 0, nil, ErrShareChecksum
	}
	return k, x, body, nil
}

// shareChecksum returns a short hash over the version, threshold, coordinate,
// and body so a typo in any field is caught at decode time.
func shareChecksum(k, x int, body []byte) []byte {
	h := sha256.New()
	h.Write([]byte{shareVersion, byte(k), byte(x)})
	h.Write(body)
	sum := h.Sum(nil)
	return sum[:checksumLen]
}
