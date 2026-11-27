// Package secret seals values at rest (AES-256-GCM) and makes/hashes one-time tokens. See DETAILS.md §Secrets.
package secret

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// prefix marks a sealed value so plain and sealed strings can never be confused.
const prefix = "enc:v1:"

// Sealer encrypts and decrypts small values with one AES-256-GCM key.
type Sealer struct {
	aead cipher.AEAD
}

// ParseKey decodes a base64 (std or url, padded or not) or hex 32-byte key.
func ParseKey(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, errors.New("encryption key is empty")
	}
	for _, dec := range []func(string) ([]byte, error){
		base64.StdEncoding.DecodeString,
		base64.RawStdEncoding.DecodeString,
		base64.URLEncoding.DecodeString,
		base64.RawURLEncoding.DecodeString,
		hex.DecodeString,
	} {
		if b, err := dec(s); err == nil && len(b) == 32 {
			return b, nil
		}
	}
	return nil, errors.New("encryption key must be 32 bytes, base64 or hex encoded (try: sam gen-key)")
}

// NewSealer builds a Sealer from a 32-byte key.
func NewSealer(key []byte) (*Sealer, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("encryption key must be 32 bytes, got %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Sealer{aead: aead}, nil
}

// Seal encrypts plaintext; aad binds the ciphertext to its purpose (e.g. the settings key).
func (s *Sealer) Seal(plaintext []byte, aad string) string {
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		panic(err)
	}
	out := s.aead.Seal(nonce, nonce, plaintext, []byte(aad))
	return prefix + base64.RawStdEncoding.EncodeToString(out)
}

// SealString is Seal for strings.
func (s *Sealer) SealString(plaintext, aad string) string { return s.Seal([]byte(plaintext), aad) }

// Open decrypts a value produced by Seal with the same aad.
func (s *Sealer) Open(sealed, aad string) ([]byte, error) {
	if !IsSealed(sealed) {
		return nil, errors.New("value is not sealed")
	}
	raw, err := base64.RawStdEncoding.DecodeString(strings.TrimPrefix(sealed, prefix))
	if err != nil {
		return nil, fmt.Errorf("sealed value: %w", err)
	}
	ns := s.aead.NonceSize()
	if len(raw) < ns {
		return nil, errors.New("sealed value too short")
	}
	pt, err := s.aead.Open(nil, raw[:ns], raw[ns:], []byte(aad))
	if err != nil {
		return nil, errors.New("sealed value cannot be decrypted (wrong SAM_ENCRYPTION_KEY?)")
	}
	return pt, nil
}

// OpenString is Open for strings.
func (s *Sealer) OpenString(sealed, aad string) (string, error) {
	b, err := s.Open(sealed, aad)
	return string(b), err
}

// IsSealed reports whether v looks like a Seal output.
func IsSealed(v string) bool { return strings.HasPrefix(v, prefix) }

// Token returns a random URL-safe token with 256 bits of entropy.
func Token() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// Hash is the at-rest form of a token: tokens are stored hashed, never in clear.
func Hash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// Equal compares two strings in constant time.
func Equal(a, b string) bool { return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1 }

// NewKey returns a fresh base64 encryption key for `sam gen-key`.
func NewKey() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.StdEncoding.EncodeToString(b)
}

// Password returns a random throwaway password (used to lock out a forced-reset account).
func Password() string {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b) + "!a1"
}
