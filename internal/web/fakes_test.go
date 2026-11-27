package web

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/specnet-io/specnet-account-manager/internal/directory"
	"github.com/specnet-io/specnet-account-manager/internal/notify"
)

// ---- in-memory directory ----

type fakeDir struct {
	mu        sync.Mutex
	users     map[string]*directory.User
	passwords map[string]string
	expired   map[string]bool
	groups    map[string]*directory.Group
	cas       [][]byte // CACertificates (DER)
	fasOnly   bool     // mimics directory.Config.FASGroups: search finds FAS groups only, new groups are FAS
}

func newFakeDir() *fakeDir {
	return &fakeDir{users: map[string]*directory.User{}, passwords: map[string]string{}, expired: map[string]bool{}, groups: map[string]*directory.Group{}}
}

func (f *fakeDir) addUser(username, email, password string, groups ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.users[username] = &directory.User{DN: "uid=" + username, Username: username, Contact: directory.Contact{GivenName: strings.ToUpper(username[:1]) + username[1:], Surname: "Test", Email: email}}
	f.passwords[username] = password
	for _, g := range groups {
		gr, ok := f.groups[g]
		if !ok {
			gr = &directory.Group{DN: "cn=" + g, Name: g}
			f.groups[g] = gr
		}
		gr.Members = append(gr.Members, username)
	}
}

func cp(u *directory.User) *directory.User {
	c := *u
	c.SSHKeys = append([]string(nil), u.SSHKeys...)
	return &c
}

func (f *fakeDir) Ping(context.Context) error { return nil }
func (f *fakeDir) CACertificates(context.Context) ([][]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.cas, nil
}
func (f *fakeDir) GetUser(_ context.Context, n string) (*directory.User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if u, ok := f.users[n]; ok {
		return cp(u), nil
	}
	return nil, directory.ErrNotFound
}
func (f *fakeDir) FindUserByEmail(_ context.Context, e string) (*directory.User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, u := range f.users {
		if strings.EqualFold(u.Email, e) {
			return cp(u), nil
		}
	}
	return nil, directory.ErrNotFound
}
func (f *fakeDir) SearchUsers(_ context.Context, q string, _ int) ([]*directory.User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []*directory.User
	for _, u := range f.users {
		if strings.Contains(u.Username, q) || strings.Contains(u.Email, q) {
			out = append(out, cp(u))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Username < out[j].Username })
	return out, nil
}
func (f *fakeDir) CreateUser(_ context.Context, nu directory.NewUser) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.users[nu.Username]; ok {
		return directory.ErrExists
	}
	f.users[nu.Username] = &directory.User{DN: "uid=" + nu.Username, Username: nu.Username, Contact: directory.Contact{GivenName: nu.GivenName, Surname: nu.Surname, Email: nu.Email}}
	return nil
}
func (f *fakeDir) SetPassword(_ context.Context, n, pw string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.users[n]; !ok {
		return directory.ErrNotFound
	}
	f.passwords[n], f.expired[n] = pw, false
	return nil
}
func (f *fakeDir) ChangePassword(_ context.Context, n, old, pw string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.passwords[n] != old || old == "" {
		return directory.ErrInvalidCreds
	}
	f.passwords[n] = pw
	return nil
}
func (f *fakeDir) ExpirePassword(_ context.Context, n string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.passwords[n], f.expired[n] = "random", true
	return nil
}
func (f *fakeDir) UpdateContact(_ context.Context, n string, c directory.Contact) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	u, ok := f.users[n]
	if !ok {
		return directory.ErrNotFound
	}
	u.Contact = c
	return nil
}
func (f *fakeDir) SetSSHKeys(_ context.Context, n string, keys []string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.users[n].SSHKeys = append([]string(nil), keys...)
	return nil
}
func (f *fakeDir) setFAS(group string, fas bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.groups[group].FAS = fas
}

func (f *fakeDir) GetGroup(_ context.Context, n string) (*directory.Group, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if g, ok := f.groups[n]; ok {
		c := *g
		c.Members = append([]string(nil), g.Members...)
		sort.Strings(c.Members)
		return &c, nil
	}
	return nil, directory.ErrNotFound
}
func (f *fakeDir) SearchGroups(_ context.Context, q string, _ int) ([]*directory.Group, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []*directory.Group
	for _, g := range f.groups {
		if strings.Contains(g.Name, q) && (!f.fasOnly || g.FAS) {
			c := *g
			out = append(out, &c)
		}
	}
	return out, nil
}
func (f *fakeDir) CreateGroup(_ context.Context, n, d, first string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.groups[n]; ok {
		return directory.ErrExists
	}
	f.groups[n] = &directory.Group{DN: "cn=" + n, Name: n, Description: d, Members: []string{first}, FAS: f.fasOnly}
	return nil
}
func (f *fakeDir) DeleteGroup(_ context.Context, n string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.groups, n)
	return nil
}
func (f *fakeDir) SetGroupDescription(_ context.Context, n, d string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.groups[n].Description = d
	return nil
}
func (f *fakeDir) AddMember(_ context.Context, g, u string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	gr, ok := f.groups[g]
	if !ok {
		return directory.ErrNotFound
	}
	if !has(gr.Members, u) {
		gr.Members = append(gr.Members, u)
	}
	return nil
}
func (f *fakeDir) RemoveMember(_ context.Context, g, u string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	gr, ok := f.groups[g]
	if !ok {
		return directory.ErrNotFound
	}
	var keep []string
	for _, m := range gr.Members {
		if m != u {
			keep = append(keep, m)
		}
	}
	gr.Members = keep
	return nil
}
func (f *fakeDir) UserGroups(_ context.Context, u string) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, g := range f.groups {
		if has(g.Members, u) {
			out = append(out, g.Name)
		}
	}
	sort.Strings(out)
	return out, nil
}

func (f *fakeDir) isMember(g, u string) bool {
	gr, _ := f.GetGroup(context.Background(), g)
	return gr != nil && has(gr.Members, u)
}

// ---- recording mail sender ----

type mailbox struct {
	mu   sync.Mutex
	msgs []notify.Message
}

func (m *mailbox) Send(_ context.Context, _ notify.Address, msg notify.Message) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.msgs = append(m.msgs, msg)
	return nil
}

func (m *mailbox) find(event, to string) *notify.Message {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := len(m.msgs) - 1; i >= 0; i-- {
		if m.msgs[i].Event == event && (to == "" || m.msgs[i].To[0] == to) {
			c := m.msgs[i]
			return &c
		}
	}
	return nil
}

func (m *mailbox) count(event string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, x := range m.msgs {
		if x.Event == event {
			n++
		}
	}
	return n
}

// ---- fake OIDC provider ----

type fakeIdP struct {
	srv      *httptest.Server
	key      *rsa.PrivateKey
	clientID string
	mu       sync.Mutex
	pending  map[string]idpGrant // code -> grant
}

type idpGrant struct {
	user, email, nonce, challenge string
}

func newFakeIdP(t *testing.T) *fakeIdP {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeIdP{key: key, clientID: "sam", pending: map[string]idpGrant{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"issuer": f.srv.URL, "authorization_endpoint": f.srv.URL + "/authorize", "token_endpoint": f.srv.URL + "/token",
			"jwks_uri": f.srv.URL + "/jwks", "id_token_signing_alg_values_supported": []string{"RS256"},
			"response_types_supported": []string{"code"}, "subject_types_supported": []string{"public"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "k1", Algorithm: "RS256", Use: "sig"}}})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		f.mu.Lock()
		g, ok := f.pending[r.PostForm.Get("code")]
		delete(f.pending, r.PostForm.Get("code"))
		f.mu.Unlock()
		sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
		if !ok || base64.RawURLEncoding.EncodeToString(sum[:]) != g.challenge {
			http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
			return
		}
		claims, _ := json.Marshal(map[string]any{"iss": f.srv.URL, "aud": f.clientID, "sub": "sub-" + g.user, "iat": time.Now().Unix(),
			"exp": time.Now().Add(5 * time.Minute).Unix(), "nonce": g.nonce, "preferred_username": g.user, "email": g.email})
		signer, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: jose.JSONWebKey{Key: key, KeyID: "k1"}}, (&jose.SignerOptions{}).WithType("JWT"))
		jws, _ := signer.Sign(claims)
		idt, _ := jws.CompactSerialize()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"access_token": "at", "token_type": "Bearer", "expires_in": 300, "id_token": idt})
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

// approve plays the user signing in at the provider: it records a code for the auth request URL.
func (f *fakeIdP) approve(authURL, user, email string) (code, state string) {
	u, _ := parseURL(authURL)
	q := u.Query()
	code = "code-" + user + "-" + q.Get("state")[:8]
	f.mu.Lock()
	f.pending[code] = idpGrant{user: user, email: email, nonce: q.Get("nonce"), challenge: q.Get("code_challenge")}
	f.mu.Unlock()
	return code, q.Get("state")
}
