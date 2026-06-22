package crypto

import (
	"bytes"
	"strings"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	token, raw, err := NewToken()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(token, TokenPrefix) {
		t.Fatalf("token %q missing prefix", token)
	}

	plaintext := []byte("the launch codes")
	sealed, err := Seal(raw, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed.Ciphertext, plaintext) {
		t.Fatal("ciphertext contains plaintext")
	}

	reparsed, err := ParseToken(token)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Open(reparsed, sealed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("got %q want %q", got, plaintext)
	}
}

func TestWrongTokenFails(t *testing.T) {
	_, raw1, _ := NewToken()
	_, raw2, _ := NewToken()
	sealed, err := Seal(raw1, []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(raw2, sealed); err != ErrDecrypt {
		t.Fatalf("want ErrDecrypt, got %v", err)
	}
}

func TestTamperedCiphertextFails(t *testing.T) {
	_, raw, _ := NewToken()
	sealed, err := Seal(raw, []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []struct {
		name string
		fn   func(*Sealed)
	}{
		{"ciphertext", func(s *Sealed) { s.Ciphertext[0] ^= 1 }},
		{"nonce", func(s *Sealed) { s.Nonce[0] ^= 1 }},
		{"salt", func(s *Sealed) { s.Salt[0] ^= 1 }},
	} {
		t.Run(mutate.name, func(t *testing.T) {
			cp := *sealed
			cp.Ciphertext = bytes.Clone(sealed.Ciphertext)
			cp.Nonce = bytes.Clone(sealed.Nonce)
			cp.Salt = bytes.Clone(sealed.Salt)
			mutate.fn(&cp)
			if _, err := Open(raw, &cp); err != ErrDecrypt {
				t.Fatalf("want ErrDecrypt, got %v", err)
			}
		})
	}
}

func TestAADSwapFails(t *testing.T) {
	// An attacker swapping ciphertexts between slots must fail GCM auth
	// because the LookupID is bound in as AAD.
	_, raw1, _ := NewToken()
	_, raw2, _ := NewToken()
	s1, _ := Seal(raw1, []byte("one"))
	s2, _ := Seal(raw2, []byte("two"))

	swapped := &Sealed{
		LookupID:   s2.LookupID, // s1's ciphertext planted under s2's slot
		Ciphertext: s1.Ciphertext,
		Salt:       s1.Salt,
		Nonce:      s1.Nonce,
	}
	if _, err := Open(raw1, swapped); err != ErrDecrypt {
		t.Fatalf("want ErrDecrypt, got %v", err)
	}
}

func TestParseTokenRejects(t *testing.T) {
	token, _, _ := NewToken()
	for _, bad := range []string{
		"",
		"ss.",
		"nope",
		token[:len(token)-1],            // truncated
		token + "A",                     // too long
		"hvs." + token[len("ss."):],     // wrong prefix
		"ss." + strings.Repeat("!", 43), // bad alphabet
	} {
		if _, err := ParseToken(bad); err != ErrBadToken {
			t.Errorf("ParseToken(%q): want ErrBadToken, got %v", bad, err)
		}
	}
	if _, err := ParseToken(token); err != nil {
		t.Errorf("valid token rejected: %v", err)
	}
}

func TestEncodeTokenRoundTrip(t *testing.T) {
	token, raw, err := NewToken()
	if err != nil {
		t.Fatal(err)
	}
	// EncodeToken is the inverse of ParseToken: raw -> canonical string.
	got, err := EncodeToken(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got != token {
		t.Fatalf("EncodeToken(raw) = %q, want %q", got, token)
	}
	reparsed, err := ParseToken(got)
	if err != nil || !bytes.Equal(reparsed, raw) {
		t.Fatalf("re-parse mismatch: %v", err)
	}
	if _, err := EncodeToken(raw[:len(raw)-1]); err != ErrBadToken {
		t.Fatalf("short raw: want ErrBadToken, got %v", err)
	}
}

func TestLookupIDDeterministicAndDistinct(t *testing.T) {
	_, raw1, _ := NewToken()
	_, raw2, _ := NewToken()
	if LookupID(raw1) != LookupID(raw1) {
		t.Fatal("LookupID not deterministic")
	}
	if LookupID(raw1) == LookupID(raw2) {
		t.Fatal("distinct tokens collided")
	}
	if len(LookupID(raw1)) != 64 {
		t.Fatalf("want 64 hex chars, got %d", len(LookupID(raw1)))
	}
}

func TestKeyDerivationDeterministic(t *testing.T) {
	_, raw, _ := NewToken()
	salt := bytes.Repeat([]byte{7}, 32)
	k1, err := deriveKey(raw, salt)
	if err != nil {
		t.Fatal(err)
	}
	k2, _ := deriveKey(raw, salt)
	if !bytes.Equal(k1, k2) {
		t.Fatal("key derivation not deterministic")
	}
	k3, _ := deriveKey(raw, bytes.Repeat([]byte{8}, 32))
	if bytes.Equal(k1, k3) {
		t.Fatal("different salts produced same key")
	}
}
