package web

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/specnet-io/specnet-account-manager/internal/notify"
	"github.com/specnet-io/specnet-account-manager/internal/secret"
	"github.com/specnet-io/specnet-account-manager/internal/settings"
	"github.com/specnet-io/specnet-account-manager/internal/store"
)

func parseURL(s string) (*url.URL, error) { return url.Parse(s) }

type harness struct {
	t        *testing.T
	srv      *httptest.Server
	base     string
	dir      *fakeDir
	mail     *mailbox
	idp      *fakeIdP
	st       *store.Store
	settings *settings.Settings
	notifier *notify.Notifier
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "sam.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	sealer, _ := secret.NewSealer(make([]byte, 32))
	s, err := settings.Load(ctx, st, sealer)
	if err != nil {
		t.Fatal(err)
	}
	h := &harness{t: t, dir: newFakeDir(), mail: &mailbox{}, idp: newFakeIdP(t), st: st, settings: s}
	for k, v := range map[string]string{"oidc_issuer": h.idp.srv.URL, "oidc_client_id": "sam", "oidc_client_secret": "s3cret", "support_email": "help@example.test"} {
		if err := s.Set(ctx, k, v, "test"); err != nil {
			t.Fatal(err)
		}
	}
	h.srv = httptest.NewUnstartedServer(nil)
	h.base = "http://" + h.srv.Listener.Addr().String()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	h.notifier = notify.New(st, sealer, s, h.base, log)
	h.notifier.SenderOverride = h.mail
	srv, err := New(Config{BaseURL: h.base, Version: "test", DatabaseKind: "SQLite"}, st, s, sealer, h.notifier, log)
	if err != nil {
		t.Fatal(err)
	}
	srv.DirectoryOverride = h.dir
	h.srv.Config.Handler = srv.Handler()
	h.srv.Start()
	t.Cleanup(h.srv.Close)

	h.dir.addUser("alice", "alice@example.test", "alice-old-password", "staff")
	h.dir.addUser("bob", "bob@example.test", "bob-password-123")
	h.dir.addUser("carol", "carol@example.test", "carol-password-123")
	h.dir.addUser("mod", "mod@example.test", "mod-password-123", "sam-moderators")
	h.dir.addUser("root", "root@example.test", "root-password-123", "sam-admins")
	return h
}

// mailLink flushes the outbox and returns the first link to path in the newest message of event to `to`.
func (h *harness) mailLink(event, to, path string) string {
	h.t.Helper()
	h.notifier.Flush(context.Background())
	m := h.mail.find(event, to)
	if m == nil {
		h.t.Fatalf("no %s email to %s", event, to)
	}
	re := regexp.MustCompile(regexp.QuoteMeta(h.base+path) + `\?t=[A-Za-z0-9_-]+`)
	link := re.FindString(m.Text)
	if link == "" {
		h.t.Fatalf("no %s link in %s email:\n%s", path, event, m.Text)
	}
	return strings.TrimPrefix(link, h.base)
}

type browser struct {
	h    *harness
	c    *http.Client
	csrf string
}

func (h *harness) browser() *browser {
	jar, _ := cookiejar.New(nil)
	host := strings.TrimPrefix(h.base, "http://")
	return &browser{h: h, c: &http.Client{Jar: jar, CheckRedirect: func(r *http.Request, _ []*http.Request) error {
		if r.URL.Host != host {
			return http.ErrUseLastResponse // stop at the identity provider
		}
		return nil
	}}}
}

var csrfRE = regexp.MustCompile(`name="csrf" value="([^"]+)"`)

func (b *browser) read(resp *http.Response, err error) (int, string) {
	b.h.t.Helper()
	if err != nil {
		b.h.t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if m := csrfRE.FindSubmatch(body); m != nil {
		b.csrf = string(m[1])
	}
	return resp.StatusCode, string(body)
}

func (b *browser) get(path string) (int, string) { return b.read(b.c.Get(b.h.base + path)) }

func (b *browser) post(path string, v url.Values) (int, string) {
	if v == nil {
		v = url.Values{}
	}
	if v.Get("csrf") == "" {
		v.Set("csrf", b.csrf)
	}
	return b.read(b.c.PostForm(b.h.base+path, v))
}

// login signs in through the fake identity provider.
func (b *browser) login(user, email string) (int, string) {
	b.h.t.Helper()
	resp, err := b.c.Get(b.h.base + "/login")
	if err != nil {
		b.h.t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		b.h.t.Fatalf("login: status %d", resp.StatusCode)
	}
	code, state := b.h.idp.approve(resp.Header.Get("Location"), user, email)
	return b.get("/auth/callback?" + url.Values{"code": {code}, "state": {state}}.Encode())
}

func must(t *testing.T, status int, body string, wantStatus int, wantText ...string) {
	t.Helper()
	if status != wantStatus {
		t.Fatalf("status %d, want %d; body:\n%s", status, wantStatus, excerpt(body))
	}
	for _, w := range wantText {
		if !strings.Contains(body, w) {
			t.Fatalf("body lacks %q:\n%s", w, excerpt(body))
		}
	}
}

func excerpt(body string) string {
	if i := strings.Index(body, "<main>"); i >= 0 {
		body = body[i:]
	}
	if len(body) > 3000 {
		body = body[:3000]
	}
	return body
}

func TestAccountRequestLifecycle(t *testing.T) {
	h := newHarness(t)
	anon := h.browser()
	st, body := anon.get("/request-account")
	must(t, st, body, 200, "Request an account")

	st, body = anon.post("/request-account", url.Values{"username": {"Dave"}, "given_name": {"Dave"}, "surname": {"Jones"}, "email": {"dave@example.test"}, "justification": {"new hire"}})
	must(t, st, body, 200, "Check your email")
	// duplicate while open
	st, body = anon.post("/request-account", url.Values{"username": {"dave"}, "given_name": {"D"}, "surname": {"J"}, "email": {"other@example.test"}, "justification": {"x"}})
	must(t, st, body, 422, "already waiting")
	// taken username
	st, body = anon.post("/request-account", url.Values{"username": {"alice"}, "given_name": {"A"}, "surname": {"B"}, "email": {"a2@example.test"}, "justification": {"x"}})
	must(t, st, body, 422, "taken")

	verify := h.mailLink("verify_request", "dave@example.test", "/verify")
	st, body = anon.get(verify)
	must(t, st, body, 200, "Confirm your email address")
	tok := strings.TrimPrefix(verify, "/verify?t=")
	st, body = anon.post("/verify", url.Values{"t": {tok}})
	must(t, st, body, 200, "email address is confirmed")
	st, body = anon.post("/verify", url.Values{"t": {tok}})
	must(t, st, body, 404) // single use
	h.notifier.Flush(context.Background())
	if h.mail.find("moderators_new_account", "mod@example.test") == nil {
		t.Fatal("moderators were not told about the request")
	}

	// a plain user cannot moderate
	alice := h.browser()
	alice.login("alice", "alice@example.test")
	st, body = alice.get("/mod/accounts")
	must(t, st, body, 403)

	mod := h.browser()
	st, body = mod.login("mod", "mod@example.test")
	must(t, st, body, 200, "Moderation")
	st, body = mod.get("/mod/accounts")
	must(t, st, body, 200, "dave@example.test", "new hire")
	reqs, _ := h.st.ListAccountRequests(context.Background(), store.StatusPending, 10)
	if len(reqs) != 1 {
		t.Fatalf("pending requests: %d", len(reqs))
	}
	st, body = mod.post("/mod/accounts/"+reqs[0].ID, url.Values{"decision": {"approve"}})
	must(t, st, body, 200, "Account dave created")
	if u, err := h.dir.GetUser(context.Background(), "dave"); err != nil || u.Email != "dave@example.test" {
		t.Fatalf("dave not created: %v", err)
	}

	setup := h.mailLink("account_approved", "dave@example.test", "/reset-password")
	dave := h.browser()
	st, body = dave.get(setup)
	must(t, st, body, 200, "Choose a password", "dave")
	tok = strings.TrimPrefix(setup, "/reset-password?t=")
	st, body = dave.post("/reset-password", url.Values{"t": {tok}, "password": {"short"}, "confirm": {"short"}})
	must(t, st, body, 422, "at least 12")
	st, body = dave.post("/reset-password", url.Values{"t": {tok}, "password": {"correct horse battery"}, "confirm": {"correct horse battery"}})
	must(t, st, body, 200, "Your password is set")
	if h.dir.passwords["dave"] != "correct horse battery" {
		t.Fatal("password not set in the directory")
	}
	st, _ = dave.post("/reset-password", url.Values{"t": {tok}, "password": {"another password!"}, "confirm": {"another password!"}})
	if st != 404 {
		t.Fatalf("reset token reusable: %d", st)
	}

	// deny path
	anon.post("/request-account", url.Values{"username": {"eve"}, "given_name": {"Eve"}, "surname": {"X"}, "email": {"eve@example.test"}, "justification": {"pls"}})
	tok = strings.TrimPrefix(h.mailLink("verify_request", "eve@example.test", "/verify"), "/verify?t=")
	anon.post("/verify", url.Values{"t": {tok}})
	reqs, _ = h.st.ListAccountRequests(context.Background(), store.StatusPending, 10)
	mod.get("/mod/accounts")
	st, body = mod.post("/mod/accounts/"+reqs[0].ID, url.Values{"decision": {"deny"}, "note": {"unknown person"}})
	must(t, st, body, 200, "denied")
	h.notifier.Flush(context.Background())
	if m := h.mail.find("account_denied", "eve@example.test"); m == nil || !strings.Contains(m.Text, "unknown person") {
		t.Fatal("denial email missing or without note")
	}
}

func TestForgotPassword(t *testing.T) {
	h := newHarness(t)
	b := h.browser()
	b.get("/forgot-password")
	st, body := b.post("/forgot-password", url.Values{"who": {"nobody"}})
	must(t, st, body, 200, "If an account matches")
	st, body = b.post("/forgot-password", url.Values{"who": {"bob@example.test"}})
	must(t, st, body, 200, "If an account matches")
	h.notifier.Flush(context.Background())
	if h.mail.count("password_reset") != 1 {
		t.Fatalf("want exactly one reset email, got %d", h.mail.count("password_reset"))
	}
	link := h.mailLink("password_reset", "bob@example.test", "/reset-password")
	b.get(link)
	st, body = b.post("/reset-password", url.Values{"t": {strings.TrimPrefix(link, "/reset-password?t=")}, "password": {"a fresh secret phrase"}, "confirm": {"a fresh secret phrase"}})
	must(t, st, body, 200, "Your password is set")
	h.notifier.Flush(context.Background())
	if h.mail.find("password_changed", "bob@example.test") == nil {
		t.Fatal("no password_changed notice")
	}
}

func TestProfileAndEmailChange(t *testing.T) {
	h := newHarness(t)
	b := h.browser()
	st, body := b.login("alice", "alice@example.test")
	must(t, st, body, 200, "Contact information", "gravatar.com/avatar/")
	st, body = b.post("/profile", url.Values{"given_name": {"Alicia"}, "surname": {"Smith"}, "display_name": {"Alicia S"}, "email": {"alicia@example.test"}, "phone": {"+1 (555) 010-0000"}, "mobile": {""}, "title": {"Engineer"}})
	must(t, st, body, 200, "We sent a link to alicia@example.test")
	u, _ := h.dir.GetUser(context.Background(), "alice")
	if u.GivenName != "Alicia" || u.Title != "Engineer" || u.Email != "alice@example.test" {
		t.Fatalf("profile not saved as expected: %+v", u.Contact)
	}
	link := h.mailLink("email_change_verify", "alicia@example.test", "/confirm-email")
	b.get(link)
	st, body = b.post("/confirm-email", url.Values{"t": {strings.TrimPrefix(link, "/confirm-email?t=")}})
	must(t, st, body, 200, "alicia@example.test")
	u, _ = h.dir.GetUser(context.Background(), "alice")
	if u.Email != "alicia@example.test" {
		t.Fatal("email not changed")
	}
	h.notifier.Flush(context.Background())
	if h.mail.find("email_changed_notice", "alice@example.test") == nil {
		t.Fatal("old address not notified")
	}
	b.get("/profile")
	st, body = b.post("/profile", url.Values{"surname": {"Smith"}, "email": {"alicia@example.test"}, "phone": {"<script>"}})
	must(t, st, body, 200, "Phone numbers may only contain")

	// change password needs the current one
	b.get("/password")
	st, body = b.post("/password", url.Values{"current": {"wrong"}, "password": {"a brand new password"}, "confirm": {"a brand new password"}})
	must(t, st, body, 422, "current password is not correct")
	st, body = b.post("/password", url.Values{"current": {"alice-old-password"}, "password": {"a brand new password"}, "confirm": {"a brand new password"}})
	must(t, st, body, 200, "Password changed")
}

func TestSSHKeys(t *testing.T) {
	h := newHarness(t)
	b := h.browser()
	b.login("bob", "bob@example.test")
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	sk, _ := ssh.NewPublicKey(pub)
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sk))) + " bob@laptop"
	b.get("/keys")
	st, body := b.post("/keys", url.Values{"key": {line}})
	must(t, st, body, 200, "Key added", strings.ReplaceAll(ssh.FingerprintSHA256(sk), "+", "&#43;"), "bob@laptop")
	st, body = b.post("/keys", url.Values{"key": {line}})
	must(t, st, body, 200, "already on your account")
	weak, _ := rsa.GenerateKey(rand.Reader, 1024)
	wk, _ := ssh.NewPublicKey(&weak.PublicKey)
	st, body = b.post("/keys", url.Values{"key": {string(ssh.MarshalAuthorizedKey(wk))}})
	must(t, st, body, 200, "at least 3072 bits")
	st, body = b.post("/keys", url.Values{"key": {`command="rm -rf /" ` + line}})
	must(t, st, body, 200, "options")
	st, body = b.post("/keys", url.Values{"key": {"-----BEGIN OPENSSH PRIVATE KEY-----"}})
	must(t, st, body, 200, "private key")
	h.notifier.Flush(context.Background())
	if h.mail.find("ssh_key_added", "bob@example.test") == nil {
		t.Fatal("no key-added notice")
	}
	st, body = b.post("/keys/delete", url.Values{"fingerprint": {ssh.FingerprintSHA256(sk)}})
	must(t, st, body, 200, "Key removed")
	if u, _ := h.dir.GetUser(context.Background(), "bob"); len(u.SSHKeys) != 0 {
		t.Fatal("key not removed")
	}
}

func TestGroupsLifecycle(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	alice := h.browser()
	alice.login("alice", "alice@example.test")
	alice.get("/groups/new")
	st, body := alice.post("/groups/new", url.Values{"name": {"Team-Red"}, "description": {"red team"}, "justification": {"we need it"}})
	must(t, st, body, 200, "sent to the moderators")
	st, body = alice.post("/groups/new", url.Values{"name": {"admins"}, "description": {"x"}, "justification": {"x"}})
	must(t, st, body, 422, "reserved")
	h.notifier.Flush(ctx)
	if h.mail.find("moderators_new_group", "mod@example.test") == nil {
		t.Fatal("moderators not told about the group request")
	}

	mod := h.browser()
	mod.login("mod", "mod@example.test")
	reqs, _ := h.st.ListGroupRequests(ctx, store.StatusPending, "", 10)
	mod.get("/mod/group-requests")
	st, body = mod.post("/mod/group-requests/"+reqs[0].ID, url.Values{"decision": {"approve"}})
	must(t, st, body, 200, "Group team-red created, owned by alice")
	if !h.dir.isMember("team-red", "alice") {
		t.Fatal("owner is not a member")
	}

	bob := h.browser()
	bob.login("bob", "bob@example.test")
	st, body = bob.get("/groups/team-red")
	must(t, st, body, 200, "Ask to join")
	if strings.Contains(body, "Members (") {
		t.Fatal("non-owner sees the member list")
	}
	st, body = bob.post("/groups/team-red/join", url.Values{"note": {"please"}})
	must(t, st, body, 200, "Request sent")
	h.notifier.Flush(ctx)
	if h.mail.find("join_request", "alice@example.test") == nil {
		t.Fatal("owner not told about the join request")
	}
	// bob cannot add himself
	st, _ = bob.post("/groups/team-red/members", url.Values{"action": {"add"}, "username": {"bob"}})
	if st != 403 {
		t.Fatalf("non-owner changed members: %d", st)
	}
	jr, _ := h.st.ListJoinRequests(ctx, "team-red", "bob", store.StatusPending)
	st, body = alice.get("/groups/team-red")
	must(t, st, body, 200, "Join requests", "please")
	st, body = alice.post("/groups/team-red/join-requests/"+jr[0].ID, url.Values{"decision": {"approve"}})
	must(t, st, body, 200, "Request approved")
	if !h.dir.isMember("team-red", "bob") {
		t.Fatal("bob not added")
	}
	st, body = alice.post("/groups/team-red/members", url.Values{"action": {"add"}, "username": {"carol"}})
	must(t, st, body, 200, "carol added")
	st, body = alice.post("/groups/team-red/members", url.Values{"action": {"remove"}, "username": {"carol"}})
	must(t, st, body, 200, "carol removed")
	h.notifier.Flush(ctx)
	if h.mail.find("membership_changed", "carol@example.test") == nil {
		t.Fatal("carol not notified")
	}
	// owners can't transfer; moderators can
	st, _ = alice.post("/groups/team-red/owners", url.Values{"action": {"transfer"}, "username": {"bob"}})
	if st != 403 {
		t.Fatalf("owner used moderator control: %d", st)
	}
	st, body = mod.post("/groups/team-red/owners", url.Values{"action": {"transfer"}, "username": {"bob"}})
	must(t, st, body, 200, "Owners updated")
	if ok, _ := h.st.IsOwner(ctx, "team-red", "bob"); !ok {
		t.Fatal("transfer failed")
	}
	if ok, _ := h.st.IsOwner(ctx, "team-red", "alice"); ok {
		t.Fatal("old owner kept")
	}
	st, _ = alice.post("/groups/team-red/members", url.Values{"action": {"remove"}, "username": {"bob"}})
	if st != 403 {
		t.Fatalf("former owner still manages: %d", st)
	}
	st, body = bob.post("/groups/team-red/leave", nil)
	must(t, st, body, 200, "You left team-red")

	// adopt an existing group; protected groups are refused
	mod.get("/mod/groups?q=staff")
	st, body = mod.post("/mod/groups/adopt", url.Values{"name": {"staff"}, "owner": {"carol"}})
	must(t, st, body, 200, "staff is now managed here")
	st, body = mod.post("/mod/groups/adopt", url.Values{"name": {"sam-admins"}})
	must(t, st, body, 200, "protected")
	st, _ = mod.get("/groups/sam-admins")
	if st != 404 {
		t.Fatalf("protected group reachable: %d", st)
	}
	st, body = mod.post("/groups/team-red/delete", url.Values{"confirm": {"team-red"}})
	must(t, st, body, 200, "deleted")
	if _, err := h.dir.GetGroup(ctx, "team-red"); err == nil {
		t.Fatal("group not deleted")
	}
}

func TestForceReset(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	carol := h.browser()
	carol.login("carol", "carol@example.test")
	mod := h.browser()
	mod.login("mod", "mod@example.test")
	st, body := mod.get("/mod/users?q=car")
	must(t, st, body, 200, "carol@example.test")
	mod.get("/mod/users/carol")
	st, body = mod.post("/mod/users/carol/force-reset", url.Values{"note": {"suspected leak"}})
	must(t, st, body, 200, "emailed a link")
	if !h.dir.expired["carol"] {
		t.Fatal("password not expired")
	}
	st, _ = carol.get("/profile")
	if st != 200 { // redirected to /login, which redirects to the IdP: stops with 302 -> we see the 302
		t.Logf("carol after reset: %d", st)
	}
	if _, err := h.st.ListAudit(ctx, "forced_reset", 10); err != nil {
		t.Fatal(err)
	}
	link := h.mailLink("password_forced", "carol@example.test", "/reset-password")
	b := h.browser()
	b.get(link)
	st, body = b.post("/reset-password", url.Values{"t": {strings.TrimPrefix(link, "/reset-password?t=")}, "password": {"fresh password 42"}, "confirm": {"fresh password 42"}})
	must(t, st, body, 200, "Your password is set")
	entries, _ := h.st.ListAudit(ctx, "password", 50)
	found := false
	for _, e := range entries {
		if e.Action == "password.forced_reset" && e.Actor == "mod" && e.Target == "carol" {
			found = true
		}
	}
	if !found {
		t.Fatal("forced reset not audited")
	}
}

func TestSessionEndsAfterForcedReset(t *testing.T) {
	h := newHarness(t)
	carol := h.browser()
	carol.login("carol", "carol@example.test")
	if st, _ := carol.get("/profile"); st != 200 {
		t.Fatal("carol not signed in")
	}
	mod := h.browser()
	mod.login("mod", "mod@example.test")
	mod.get("/mod/users/carol")
	mod.post("/mod/users/carol/force-reset", nil)
	resp, err := carol.c.Get(h.base + "/profile")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound || !strings.HasPrefix(resp.Header.Get("Location"), h.idp.srv.URL) {
		t.Fatalf("carol still signed in: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
}

func TestAdminSettingsAndRoles(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	mod := h.browser()
	mod.login("mod", "mod@example.test")
	if st, _ := mod.get("/admin"); st != 403 {
		t.Fatalf("moderator reached admin: %d", st)
	}
	root := h.browser()
	st, body := root.login("root", "root@example.test")
	must(t, st, body, 200, "Administration")
	if strings.Contains(body, ">Moderation<") {
		t.Fatal("admin got moderator nav")
	}
	st, body = root.get("/admin")
	must(t, st, body, 200, "Mailjet API secret", h.base+"/auth/callback")
	if strings.Contains(body, "s3cret") {
		t.Fatal("secret rendered in the admin page")
	}
	st, body = root.post("/admin/settings", url.Values{"section": {"Notifications"}, "notify_provider": {"mailjet"}, "mail_from_address": {"noreply@example.test"},
		"mailjet_api_key": {"public-key"}, "mailjet_api_secret": {"very-secret-value"}, "mailjet_api_url": {"https://api.mailjet.com/v3.1/send"}, "smtp_port": {"587"}, "smtp_security": {"starttls"}})
	must(t, st, body, 200, "Notifications saved")
	raw, _ := h.st.AllSettings(ctx)
	if !secret.IsSealed(raw["mailjet_api_secret"]) || strings.Contains(raw["mailjet_api_secret"], "very-secret") {
		t.Fatalf("secret stored in clear: %q", raw["mailjet_api_secret"])
	}
	if h.settings.Get("mailjet_api_secret") != "very-secret-value" {
		t.Fatal("secret not readable back")
	}
	// blank secret keeps the stored one
	root.get("/admin")
	root.post("/admin/settings", url.Values{"section": {"Notifications"}, "notify_provider": {"mailjet"}, "mail_from_address": {"noreply@example.test"}, "mailjet_api_url": {"https://api.mailjet.com/v3.1/send"}, "smtp_port": {"587"}, "smtp_security": {"starttls"}})
	if h.settings.Get("mailjet_api_secret") != "very-secret-value" {
		t.Fatal("blank field wiped the secret")
	}
	st, body = root.post("/admin/settings", url.Values{"section": {"General"}, "username_pattern": {"("}, "site_name": {"Specnet"}})
	must(t, st, body, 200, "Not saved", "invalid regular expression")
	entries, _ := h.st.ListAudit(ctx, "settings.changed", 10)
	for _, e := range entries {
		if strings.Contains(e.Detail, "very-secret") {
			t.Fatal("secret value written to the audit log")
		}
	}
	if st, _ := root.get("/activity"); st != 200 {
		t.Fatal("admin cannot read activity")
	}
}

func TestAdminLinkBootstrap(t *testing.T) {
	h := newHarness(t)
	tok := secret.Token()
	if err := h.st.PutToken(context.Background(), &store.Token{Hash: secret.Hash(tok), Purpose: store.PurposeAdminLink, Subject: "bootstrap", ExpiresAt: time.Now().Add(time.Minute)}, false); err != nil {
		t.Fatal(err)
	}
	b := h.browser()
	st, body := b.get("/admin-link?t=" + tok)
	must(t, st, body, 200, "One-time setup sign-in")
	st, body = b.post("/admin-link", url.Values{"t": {tok}})
	must(t, st, body, 200, "Administration", "Setup administrator")
	if st, _ := b.get("/profile"); st != 403 {
		t.Fatalf("setup admin reached user pages: %d", st)
	}
	other := h.browser()
	other.get("/forgot-password")
	if st, _ := other.post("/admin-link", url.Values{"t": {tok}}); st != 404 {
		t.Fatal("admin link reusable")
	}
}

func TestSecurityBasics(t *testing.T) {
	h := newHarness(t)
	b := h.browser()
	b.get("/forgot-password")
	st, _ := b.post("/forgot-password", url.Values{"who": {"bob"}, "csrf": {"forged"}})
	if st != 403 {
		t.Fatalf("CSRF not enforced: %d", st)
	}
	req, _ := http.NewRequest(http.MethodPost, h.base+"/forgot-password", strings.NewReader(url.Values{"who": {"bob"}, "csrf": {b.csrf}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://evil.example")
	resp, err := b.c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Fatalf("cross-origin POST allowed: %d", resp.StatusCode)
	}
	resp, _ = b.c.Get(h.base + "/")
	resp.Body.Close()
	for _, hdr := range []string{"Content-Security-Policy", "X-Frame-Options", "Referrer-Policy"} {
		if resp.Header.Get(hdr) == "" {
			t.Fatalf("missing %s", hdr)
		}
	}
	// unknown OIDC user
	st, body := h.browser().login("mallory", "m@example.test")
	must(t, st, body, 403, "No account found", "mallory")
	// open redirect
	if got := safeNext("//evil.example/x"); got != "/" {
		t.Fatalf("safeNext allowed %q", got)
	}
	// tampered callback state
	c := h.browser()
	resp, _ = c.c.Get(h.base + "/login")
	resp.Body.Close()
	code, _ := h.idp.approve(resp.Header.Get("Location"), "alice", "alice@example.test")
	st, _ = c.get("/auth/callback?code=" + code + "&state=wrong")
	if st != 400 {
		t.Fatalf("bad state accepted: %d", st)
	}
}

func mustPrefixes(s ...string) []netip.Prefix {
	var out []netip.Prefix
	for _, p := range s {
		out = append(out, netip.MustParsePrefix(p))
	}
	return out
}

func TestProxyClientIP(t *testing.T) {
	s := &Server{}
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "10.0.0.5:1234"
	r.Header.Set("X-Forwarded-For", "203.0.113.9, 10.0.0.4")
	if ip := s.clientIP(r); ip != "10.0.0.5" {
		t.Fatalf("untrusted proxy honoured: %s", ip)
	}
	s.cfg.TrustedProxies = mustPrefixes("10.0.0.0/8")
	if ip := s.clientIP(r); ip != "203.0.113.9" {
		t.Fatalf("trusted proxy: got %s", ip)
	}
}
