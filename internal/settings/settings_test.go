package settings

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/specnet-io/specnet-account-manager/internal/secret"
	"github.com/specnet-io/specnet-account-manager/internal/store"
)

func load(t *testing.T) (*Settings, *store.Store) {
	t.Helper()
	st, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "s.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	sealer, _ := secret.NewSealer(make([]byte, 32))
	s, err := Load(context.Background(), st, sealer)
	if err != nil {
		t.Fatal(err)
	}
	return s, st
}

func TestDefaultsDBAndEnv(t *testing.T) {
	t.Setenv("SAM_SITE_NAME", "From Env")
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "pw"), []byte("file-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SAM_LDAP_BIND_PASSWORD_FILE", filepath.Join(dir, "pw"))
	s, st := load(t)
	ctx := context.Background()
	if s.Get("moderator_group") != "sam-moderators" {
		t.Fatal("default")
	}
	if s.Get("site_name") != "From Env" || !s.Locked("site_name") {
		t.Fatal("env override")
	}
	if err := s.Set(ctx, "site_name", "x", "t"); err == nil {
		t.Fatal("locked setting changed")
	}
	if s.Get("ldap_bind_password") != "file-secret" {
		t.Fatal("_FILE not read")
	}
	if err := s.Set(ctx, "smtp_password", "pw123", "t"); err != nil {
		t.Fatal(err)
	}
	raw, _ := st.AllSettings(ctx)
	if !secret.IsSealed(raw["smtp_password"]) {
		t.Fatal("secret stored in clear")
	}
	if s.Get("smtp_password") != "pw123" {
		t.Fatal("secret read back")
	}
	for key, bad := range map[string]string{
		"session_hours":   "0",
		"notify_provider": "pigeon",
		"ldap_url":        "http://x",
		"ldap_ca_cert":    "not pem",
		"editable_fields": "email, shoe_size",
		"oidc_issuer":     "ftp://x",
	} {
		if err := s.Set(ctx, key, bad, "t"); err == nil {
			t.Fatalf("%s=%q accepted", key, bad)
		}
	}
	if err := s.Set(ctx, "editable_fields", "email,\n phone", "t"); err != nil {
		t.Fatal(err)
	}
	if l := s.List("editable_fields"); len(l) != 2 || l[1] != "phone" {
		t.Fatalf("list: %v", l)
	}
	v := s.Version()
	if err := s.Set(ctx, "session_hours", "8", "t"); err != nil {
		t.Fatal(err)
	}
	if s.Version() == v || s.Int("session_hours") != 8 {
		t.Fatal("version/int")
	}
	if err := s.Set(ctx, "session_hours", "", "t"); err != nil || s.Int("session_hours") != 12 {
		t.Fatal("reset to default")
	}
}

func TestBadEnvFails(t *testing.T) {
	t.Setenv("SAM_SESSION_HOURS", "lots")
	st, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "s.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	sealer, _ := secret.NewSealer(make([]byte, 32))
	if _, err := Load(context.Background(), st, sealer); err == nil {
		t.Fatal("invalid env accepted")
	}
}
