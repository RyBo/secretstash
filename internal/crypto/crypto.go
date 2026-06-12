// Package crypto implements secretstash's zero-knowledge sealing scheme.
//
// The wrap token is the only key material. The server stores ciphertext,
// salt, nonce, and SHA-256(token) — nothing stored can decrypt a secret.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
)

const (
	// TokenPrefix marks secretstash tokens for grep-ability and future
	// versioning, like Vault's "hvs." prefix.
	TokenPrefix = "ss."

	tokenBytes = 32 // 256 bits of crypto/rand entropy
	saltBytes  = 32
	nonceBytes = 12

	hkdfInfo = "secretstash/v1/aead"
)

var (
	ErrBadToken  = errors.New("invalid token")
	ErrDecrypt   = errors.New("decryption failed: wrong token or tampered ciphertext")
	tokenEncoder = base64.RawURLEncoding
)

// Sealed is everything the server stores for one secret. None of these
// fields can recover the plaintext without the original token.
type Sealed struct {
	LookupID   string // hex SHA-256 of the raw token; map key and AAD
	Ciphertext []byte
	Salt       []byte
	Nonce      []byte
}

// NewToken returns a fresh wrap token ("ss." + base64url of 32 random bytes)
// alongside its raw bytes.
func NewToken() (token string, raw []byte, err error) {
	raw = make([]byte, tokenBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", nil, fmt.Errorf("generating token: %w", err)
	}
	return TokenPrefix + tokenEncoder.EncodeToString(raw), raw, nil
}

// ParseToken validates the token format and returns the raw token bytes.
// All failure modes return the same generic error to avoid oracle behavior.
func ParseToken(token string) ([]byte, error) {
	if len(token) < len(TokenPrefix) || token[:len(TokenPrefix)] != TokenPrefix {
		return nil, ErrBadToken
	}
	raw, err := tokenEncoder.DecodeString(token[len(TokenPrefix):])
	if err != nil || len(raw) != tokenBytes {
		return nil, ErrBadToken
	}
	return raw, nil
}

// LookupID derives the storage key from raw token bytes. The token has 256
// bits of entropy, so SHA-256 preimage resistance makes the hash safe to
// store, and the map lookup itself serves as the auth check — there is no
// secret-dependent comparison that would need to be constant-time. If direct
// hash comparison is ever added, use subtle.ConstantTimeCompare.
func LookupID(rawToken []byte) string {
	sum := sha256.Sum256(rawToken)
	return hex.EncodeToString(sum[:])
}

// Seal encrypts plaintext under a key derived from the token. The returned
// Sealed contains no decryption capability. The derived key is zeroed before
// returning; callers should zero rawToken and plaintext when done (best
// effort — Go's GC may have made copies).
func Seal(rawToken, plaintext []byte) (*Sealed, error) {
	salt := make([]byte, saltBytes)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("generating salt: %w", err)
	}
	nonce := make([]byte, nonceBytes)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generating nonce: %w", err)
	}

	id := LookupID(rawToken)
	key, err := deriveKey(rawToken, salt)
	if err != nil {
		return nil, err
	}
	defer wipe(key)

	aead, err := newAEAD(key)
	if err != nil {
		return nil, err
	}
	ct := aead.Seal(nil, nonce, plaintext, []byte(id))
	return &Sealed{LookupID: id, Ciphertext: ct, Salt: salt, Nonce: nonce}, nil
}

// Open decrypts a Sealed entry with the raw token. The AAD binds the
// ciphertext to its LookupID, so an entry swapped into another slot fails
// authentication.
func Open(rawToken []byte, s *Sealed) ([]byte, error) {
	key, err := deriveKey(rawToken, s.Salt)
	if err != nil {
		return nil, err
	}
	defer wipe(key)

	aead, err := newAEAD(key)
	if err != nil {
		return nil, err
	}
	pt, err := aead.Open(nil, s.Nonce, s.Ciphertext, []byte(s.LookupID))
	if err != nil {
		return nil, ErrDecrypt
	}
	return pt, nil
}

func deriveKey(rawToken, salt []byte) ([]byte, error) {
	key, err := hkdf.Key(sha256.New, rawToken, salt, hkdfInfo, 32)
	if err != nil {
		return nil, fmt.Errorf("deriving key: %w", err)
	}
	return key, nil
}

func newAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// Wipe zeroes b in place. Best effort: Go's GC can move/copy memory, so this
// is hardening, not a guarantee. The real guarantee is that the server only
// retains ciphertext.
func Wipe(b []byte) { wipe(b) }

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
