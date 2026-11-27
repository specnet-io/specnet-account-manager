//go:build integration

// Runs against a real OpenLDAP server; see test/integration.sh.
package directory

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/go-ldap/ldap/v3"
	"golang.org/x/crypto/ssh"
)

func itConfig(t *testing.T) Config {
	url := os.Getenv("SAM_TEST_LDAP_URL")
	if url == "" {
		t.Skip("SAM_TEST_LDAP_URL not set")
	}
	return Config{
		Profile:            "openldap",
		URL:                url,
		StartTLS:           strings.HasPrefix(url, "ldap://"),
		InsecureSkipVerify: true, // the test server has a self-signed certificate
		BindDN:             os.Getenv("SAM_TEST_LDAP_BIND_DN"),
		BindPassword:       os.Getenv("SAM_TEST_LDAP_BIND_PASSWORD"),
		BaseDN:             os.Getenv("SAM_TEST_LDAP_BASE_DN"),
	}
}

func ensureOU(t *testing.T, l *LDAP, dn, ou string) {
	conn, err := l.service(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	req := ldap.NewAddRequest(dn, nil)
	req.Attribute("objectClass", []string{"organizationalUnit"})
	req.Attribute("ou", []string{ou})
	if err := conn.Add(req); err != nil && !ldap.IsErrorWithCode(err, ldap.LDAPResultEntryAlreadyExists) {
		t.Fatal(err)
	}
}

func TestOpenLDAPIntegration(t *testing.T) {
	ctx := context.Background()
	l, err := NewLDAP(itConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	ensureOU(t, l, "ou=people,"+l.cfg.BaseDN, "people")
	ensureOU(t, l, "ou=groups,"+l.cfg.BaseDN, "groups")
	if err := l.Ping(ctx); err != nil {
		t.Fatal(err)
	}

	suffix := strings.ToLower(rand.Text()[:6])
	alice, bob := "alice"+suffix, "bob"+suffix
	group := "team" + suffix
	for _, u := range []string{alice, bob} {
		if err := l.CreateUser(ctx, NewUser{Username: u, GivenName: "Test", Surname: u, Email: u + "@sam.test"}); err != nil {
			t.Fatalf("create %s: %v", u, err)
		}
	}
	if err := l.CreateUser(ctx, NewUser{Username: alice, GivenName: "x", Surname: "y", Email: "z@sam.test"}); !errors.Is(err, ErrExists) {
		t.Fatalf("duplicate: %v", err)
	}
	ua, err := l.GetUser(ctx, alice)
	if err != nil || ua.Email != alice+"@sam.test" || ua.Name() != "Test "+alice {
		t.Fatalf("get: %+v %v", ua, err)
	}
	ub, _ := l.GetUser(ctx, bob)
	if ua.DN == ub.DN {
		t.Fatal("same DN")
	}
	if u, err := l.FindUserByEmail(ctx, bob+"@sam.test"); err != nil || u.Username != bob {
		t.Fatalf("by email: %v", err)
	}
	if _, err := l.GetUser(ctx, "nobody"+suffix); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing user: %v", err)
	}
	if found, err := l.SearchUsers(ctx, suffix, 10); err != nil || len(found) != 2 {
		t.Fatalf("search: %d %v", len(found), err)
	}

	// passwords
	if err := l.SetPassword(ctx, alice, "first password 123"); err != nil {
		t.Fatal(err)
	}
	if err := l.ChangePassword(ctx, alice, "wrong", "second password 123"); !errors.Is(err, ErrInvalidCreds) {
		t.Fatalf("wrong old password: %v", err)
	}
	if err := l.ChangePassword(ctx, alice, "first password 123", "second password 123"); err != nil {
		t.Fatal(err)
	}
	if err := l.ExpirePassword(ctx, alice); err != nil {
		t.Fatal(err)
	}
	if err := l.ChangePassword(ctx, alice, "second password 123", "third password 123"); !errors.Is(err, ErrInvalidCreds) {
		t.Fatalf("old password still works after forced reset: %v", err)
	}

	// contact
	c := ua.Contact
	c.Phone, c.Title, c.DisplayName, c.GivenName = "+1 555 0100", "Tester", "Ali", "Alicia"
	if err := l.UpdateContact(ctx, alice, c); err != nil {
		t.Fatal(err)
	}
	ua, _ = l.GetUser(ctx, alice)
	if ua.Phone != "+1 555 0100" || ua.Title != "Tester" || ua.DisplayName != "Ali" || ua.GivenName != "Alicia" {
		t.Fatalf("contact: %+v", ua.Contact)
	}
	c = ua.Contact
	c.Title = ""
	if err := l.UpdateContact(ctx, alice, c); err != nil {
		t.Fatal(err)
	}
	if ua, _ = l.GetUser(ctx, alice); ua.Title != "" {
		t.Fatal("title not cleared")
	}

	// ssh keys (adds the ldapPublicKey class on first use)
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	sk, _ := ssh.NewPublicKey(pub)
	key := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sk))) + " it@test"
	if err := l.SetSSHKeys(ctx, alice, []string{key}); err != nil {
		t.Fatal(err)
	}
	if ua, _ = l.GetUser(ctx, alice); len(ua.SSHKeys) != 1 || ua.SSHKeys[0] != key {
		t.Fatalf("keys: %v", ua.SSHKeys)
	}
	if err := l.SetSSHKeys(ctx, alice, nil); err != nil {
		t.Fatal(err)
	}
	if ua, _ = l.GetUser(ctx, alice); len(ua.SSHKeys) != 0 {
		t.Fatal("keys not cleared")
	}

	// groups
	if err := l.CreateGroup(ctx, group, "it group", alice); err != nil {
		t.Fatal(err)
	}
	if err := l.CreateGroup(ctx, group, "", alice); !errors.Is(err, ErrExists) {
		t.Fatalf("duplicate group: %v", err)
	}
	if err := l.AddMember(ctx, group, bob); err != nil {
		t.Fatal(err)
	}
	if err := l.AddMember(ctx, group, bob); err != nil {
		t.Fatalf("add twice: %v", err)
	}
	g, err := l.GetGroup(ctx, group)
	if err != nil || len(g.Members) != 2 || g.Description != "it group" {
		t.Fatalf("group: %+v %v", g, err)
	}
	if gs, _ := l.UserGroups(ctx, bob); len(gs) != 1 || gs[0] != group {
		t.Fatalf("user groups: %v", gs)
	}
	if found, _ := l.SearchGroups(ctx, suffix, 10); len(found) != 1 {
		t.Fatal("group search")
	}
	if err := l.SetGroupDescription(ctx, group, "changed"); err != nil {
		t.Fatal(err)
	}
	if err := l.RemoveMember(ctx, group, bob); err != nil {
		t.Fatal(err)
	}
	if err := l.RemoveMember(ctx, group, bob); err != nil {
		t.Fatalf("remove twice: %v", err)
	}
	if err := l.RemoveMember(ctx, group, alice); err == nil || !strings.Contains(err.Error(), "at least one member") {
		t.Fatalf("removing the last member: %v", err)
	}
	if err := l.DeleteGroup(ctx, group); err != nil {
		t.Fatal(err)
	}
	if _, err := l.GetGroup(ctx, group); !errors.Is(err, ErrNotFound) {
		t.Fatal("group not deleted")
	}

	// bad service credentials
	bad := itConfig(t)
	bad.BindPassword = "wrong"
	lb, _ := NewLDAP(bad)
	if err := lb.Ping(ctx); err == nil || !strings.Contains(err.Error(), "service account") {
		t.Fatalf("bad bind: %v", err)
	}
}
