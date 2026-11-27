package secret

import (
	"strings"
	"testing"
)

func TestSealRoundTrip(t *testing.T) {
	key, err := ParseKey(NewKey())
	if err != nil {
		t.Fatal(err)
	}
	s, _ := NewSealer(key)
	sealed := s.SealString("hunter2", "setting:x")
	if !IsSealed(sealed) || strings.Contains(sealed, "hunter2") {
		t.Fatalf("not sealed: %s", sealed)
	}
	if s.SealString("hunter2", "setting:x") == sealed {
		t.Fatal("nonce reuse")
	}
	if pt, err := s.OpenString(sealed, "setting:x"); err != nil || pt != "hunter2" {
		t.Fatalf("open: %q %v", pt, err)
	}
	if _, err := s.OpenString(sealed, "setting:y"); err == nil {
		t.Fatal("opened with the wrong purpose")
	}
	other, _ := NewSealer(make([]byte, 32))
	if _, err := other.OpenString(sealed, "setting:x"); err == nil {
		t.Fatal("opened with the wrong key")
	}
}

func TestParseKey(t *testing.T) {
	for _, bad := range []string{"", "short", strings.Repeat("a", 44)} {
		if _, err := ParseKey(bad); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
	if _, err := ParseKey(strings.Repeat("ab", 32)); err != nil {
		t.Fatalf("hex key: %v", err)
	}
}

func TestTokenHash(t *testing.T) {
	a, b := Token(), Token()
	if a == b || len(a) < 40 {
		t.Fatal("weak tokens")
	}
	if Hash(a) == a || Hash(a) != Hash(a) {
		t.Fatal("hash")
	}
}
