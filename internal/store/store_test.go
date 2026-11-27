package store

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// SAM_TEST_POSTGRES=postgres://... also runs these against Postgres.
func stores(t *testing.T) map[string]*Store {
	ctx := context.Background()
	out := map[string]*Store{}
	s, err := Open(ctx, "sqlite://"+filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	out["sqlite"] = s
	if url := os.Getenv("SAM_TEST_POSTGRES"); url != "" {
		p, err := Open(ctx, url)
		if err != nil {
			t.Fatal(err)
		}
		for _, tbl := range []string{"settings", "sessions", "tokens", "account_requests", "group_requests", "join_requests", "managed_groups", "group_owners", "audit", "outbox"} {
			if _, err := p.db.Exec("DELETE FROM " + tbl); err != nil {
				t.Fatal(err)
			}
		}
		t.Cleanup(func() { p.Close() })
		out["postgres"] = p
	}
	return out
}

func TestStore(t *testing.T) {
	for name, s := range stores(t) {
		t.Run(name, func(t *testing.T) { exercise(t, s) })
	}
}

func exercise(t *testing.T, s *Store) {
	ctx := context.Background()
	if err := s.migrate(ctx); err != nil { // idempotent
		t.Fatal(err)
	}
	if err := s.PutSetting(ctx, "a", "1", "x"); err != nil {
		t.Fatal(err)
	}
	if err := s.PutSetting(ctx, "a", "2", "x"); err != nil {
		t.Fatal(err)
	}
	if all, _ := s.AllSettings(ctx); all["a"] != "2" {
		t.Fatalf("upsert: %v", all)
	}

	// tokens: replace, purpose, single use, expiry
	must(t, s.PutToken(ctx, &Token{Hash: "h1", Purpose: PurposePassword, Subject: "u", ExpiresAt: time.Now().Add(time.Hour)}, true))
	must(t, s.PutToken(ctx, &Token{Hash: "h2", Purpose: PurposePassword, Subject: "u", ExpiresAt: time.Now().Add(time.Hour)}, true))
	if _, err := s.PeekToken(ctx, "h1", PurposePassword); err != ErrNotFound {
		t.Fatal("replace kept the old token")
	}
	if _, err := s.TakeToken(ctx, "h2", PurposeVerifyRequest); err != ErrNotFound {
		t.Fatal("wrong purpose accepted")
	}
	if tk, err := s.TakeToken(ctx, "h2", PurposePassword); err != nil || tk.Subject != "u" {
		t.Fatal(err)
	}
	if _, err := s.TakeToken(ctx, "h2", PurposePassword); err != ErrNotFound {
		t.Fatal("token reused")
	}
	must(t, s.PutToken(ctx, &Token{Hash: "h3", Purpose: PurposePassword, Subject: "v", ExpiresAt: time.Now().Add(-time.Second)}, false))
	if _, err := s.PeekToken(ctx, "h3", PurposePassword); err != ErrNotFound {
		t.Fatal("expired token accepted")
	}

	// account requests
	r := &AccountRequest{Username: "dave", Email: "Dave@x.test", Status: StatusUnverified}
	must(t, s.CreateAccountRequest(ctx, r))
	if open, _ := s.OpenAccountRequestFor(ctx, "other", "dave@X.test"); !open {
		t.Fatal("email match should be case-insensitive")
	}
	if err := s.SetAccountRequestStatus(ctx, r.ID, StatusPending, StatusApproved, "m", ""); err != ErrNotFound {
		t.Fatal("status guard ignored")
	}
	must(t, s.SetAccountRequestStatus(ctx, r.ID, StatusUnverified, StatusPending, "", ""))
	if l, _ := s.ListAccountRequests(ctx, StatusPending, 10); len(l) != 1 {
		t.Fatal("pending list")
	}

	// managed groups and owners
	must(t, s.AddManagedGroup(ctx, "g1", "mod", "alice"))
	must(t, s.AddManagedGroup(ctx, "g1", "mod", "alice"))
	must(t, s.AddOwner(ctx, "g1", "bob"))
	if o, _ := s.Owners(ctx, "g1"); len(o) != 2 {
		t.Fatalf("owners: %v", o)
	}
	must(t, s.TransferOwnership(ctx, "g1", "carol"))
	if g, _ := s.GetManagedGroup(ctx, "g1"); len(g.Owners) != 1 || g.Owners[0] != "carol" {
		t.Fatalf("transfer: %v", g.Owners)
	}
	if l, _ := s.ListManagedGroups(ctx); len(l) != 1 || l[0].Owners[0] != "carol" {
		t.Fatal("list managed")
	}
	must(t, s.RemoveManagedGroup(ctx, "g1"))
	if _, err := s.GetManagedGroup(ctx, "g1"); err != ErrNotFound {
		t.Fatal("remove")
	}

	// sessions
	se := &Session{IDHash: "sh", Username: "alice", Roles: []string{"user", "moderator"}, CSRF: "c", CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour), RefreshedAt: time.Now()}
	must(t, s.CreateSession(ctx, se))
	if got, err := s.GetSession(ctx, "sh"); err != nil || !got.HasRole("moderator") {
		t.Fatal("session roles")
	}
	must(t, s.DeleteUserSessions(ctx, "alice"))
	if _, err := s.GetSession(ctx, "sh"); err != ErrNotFound {
		t.Fatal("sessions not deleted")
	}

	// outbox
	must(t, s.Enqueue(ctx, "sealed"))
	due, _ := s.DueOutbox(ctx, 10)
	if len(due) != 1 {
		t.Fatal("due")
	}
	must(t, s.MarkFailed(ctx, due[0].ID, 1, 3, time.Now().Add(time.Hour), "boom"))
	if due, _ := s.DueOutbox(ctx, 10); len(due) != 0 {
		t.Fatal("backoff ignored")
	}
	if st, _ := s.OutboxStats(ctx); st["queued"] != 1 {
		t.Fatalf("stats %v", st)
	}

	must(t, s.Audit(ctx, "alice", "x.y", "t", "d", "1.2.3.4"))
	if l, _ := s.ListAudit(ctx, "alice", 10); len(l) != 1 {
		t.Fatal("audit")
	}
	must(t, s.Cleanup(ctx, time.Hour))
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
