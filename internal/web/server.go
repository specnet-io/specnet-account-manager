// Package web is the HTTP UI: routing, middleware, sessions and the page handlers. See DETAILS.md §Web.
package web

import (
	"context"
	"embed"
	"errors"
	"html/template"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/specnet-io/specnet-account-manager/internal/auth"
	"github.com/specnet-io/specnet-account-manager/internal/directory"
	"github.com/specnet-io/specnet-account-manager/internal/notify"
	"github.com/specnet-io/specnet-account-manager/internal/secret"
	"github.com/specnet-io/specnet-account-manager/internal/settings"
	"github.com/specnet-io/specnet-account-manager/internal/store"
)

//go:embed templates/*.html static/*
var assets embed.FS

// Config is the static (env-only) part of the web server.
type Config struct {
	BaseURL        string         // public URL, e.g. https://accounts.example.com
	TrustedProxies []netip.Prefix // peers allowed to set X-Forwarded-For
	Version        string
	DatabaseKind   string
}

// Server holds the app's dependencies.
type Server struct {
	cfg      Config
	store    *store.Store
	settings *settings.Settings
	sealer   *secret.Sealer
	notifier *notify.Notifier
	oidc     *auth.OIDC
	log      *slog.Logger
	pages    map[string]*template.Template
	limiter  *limiter
	secure   bool
	base     *url.URL

	// DirectoryOverride replaces the LDAP client (tests).
	DirectoryOverride directory.Directory
	dirMu             sync.Mutex
	dirVersion        uint64
	dir               directory.Directory
	dirErr            error
}

// New builds the server.
func New(cfg Config, st *store.Store, s *settings.Settings, sealer *secret.Sealer, n *notify.Notifier, log *slog.Logger) (*Server, error) {
	base, err := url.Parse(strings.TrimRight(cfg.BaseURL, "/"))
	if err != nil || (base.Scheme != "http" && base.Scheme != "https") || base.Host == "" {
		return nil, errors.New("SAM_BASE_URL must be the public http(s) URL of this site")
	}
	cfg.BaseURL = base.String()
	srv := &Server{
		cfg: cfg, store: st, settings: s, sealer: sealer, notifier: n, log: log,
		oidc:    auth.New(s, cfg.BaseURL+"/auth/callback"),
		limiter: newLimiter(),
		secure:  base.Scheme == "https",
		base:    base,
	}
	if err := srv.parseTemplates(); err != nil {
		return nil, err
	}
	return srv, nil
}

// Dir returns the directory client for the current settings.
func (s *Server) Dir() (directory.Directory, error) {
	if s.DirectoryOverride != nil {
		return s.DirectoryOverride, nil
	}
	s.dirMu.Lock()
	defer s.dirMu.Unlock()
	if v := s.settings.Version(); (s.dir == nil && s.dirErr == nil) || s.dirVersion != v {
		s.dirVersion = v
		l, err := directory.NewLDAP(directory.Config{
			Profile:            s.settings.Get("ldap_profile"),
			URL:                s.settings.Get("ldap_url"),
			StartTLS:           s.settings.Bool("ldap_starttls"),
			CACert:             s.settings.Get("ldap_ca_cert"),
			InsecureSkipVerify: s.settings.Bool("ldap_insecure_skip_verify"),
			BindDN:             s.settings.Get("ldap_bind_dn"),
			BindPassword:       s.settings.Get("ldap_bind_password"),
			BaseDN:             s.settings.Get("ldap_base_dn"),
			UserBase:           s.settings.Get("ldap_user_base"),
			GroupBase:          s.settings.Get("ldap_group_base"),
			Realm:              s.settings.Get("ldap_kerberos_realm"),
			SSHAttr:            s.settings.Get("ldap_ssh_key_attribute"),
			IDMin:              s.settings.Int("ldap_id_min"),
			HomePrefix:         s.settings.Get("ldap_home_prefix"),
			Shell:              s.settings.Get("ldap_login_shell"),
			Timeout:            time.Duration(s.settings.Int("ldap_timeout_seconds")) * time.Second,
			FASGroups:          s.fasOnly(),
		})
		s.dir, s.dirErr = nil, err
		if err == nil {
			s.dir = l
		}
	}
	if s.dirErr != nil {
		return nil, s.dirErr
	}
	return s.dir, nil
}

// Handler returns the full middleware-wrapped router.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	static, _ := fs.Sub(assets, "static")
	mux.Handle("GET /static/", http.StripPrefix("/static/", staticHandler(http.FileServerFS(static))))
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok\n")) })
	mux.HandleFunc("GET /readyz", s.readyz)

	// public
	mux.HandleFunc("GET /{$}", s.home)
	mux.HandleFunc("GET /login", s.login)
	mux.HandleFunc("GET /auth/callback", s.callback)
	mux.HandleFunc("POST /logout", s.logout)
	mux.HandleFunc("GET /request-account", s.requestAccountForm)
	mux.HandleFunc("POST /request-account", s.requestAccount)
	mux.HandleFunc("GET /verify", s.tokenConfirmPage("verify", store.PurposeVerifyRequest))
	mux.HandleFunc("POST /verify", s.verifyRequest)
	mux.HandleFunc("GET /forgot-password", s.forgotForm)
	mux.HandleFunc("POST /forgot-password", s.forgot)
	mux.HandleFunc("GET /reset-password", s.resetForm)
	mux.HandleFunc("POST /reset-password", s.reset)
	mux.HandleFunc("GET /confirm-email", s.tokenConfirmPage("confirm_email", store.PurposeEmailChange))
	mux.HandleFunc("POST /confirm-email", s.confirmEmail)
	mux.HandleFunc("GET /admin-link", s.tokenConfirmPage("admin_link", store.PurposeAdminLink))
	mux.HandleFunc("POST /admin-link", s.adminLink)

	// signed-in users
	user := func(h http.HandlerFunc) http.Handler { return s.require(roleUser, h) }
	mux.Handle("GET /home", user(s.userHome))
	mux.Handle("GET /certs/{file}", user(s.certDownload))
	mux.Handle("GET /profile", user(s.profile))
	mux.Handle("POST /profile", user(s.updateProfile))
	mux.Handle("GET /password", user(s.passwordForm))
	mux.Handle("POST /password", user(s.changePassword))
	mux.Handle("GET /keys", user(s.keys))
	mux.Handle("POST /keys", user(s.addKey))
	mux.Handle("POST /keys/delete", user(s.deleteKey))
	mux.Handle("GET /groups", user(s.groups))
	mux.Handle("GET /groups/new", user(s.groupRequestForm))
	mux.Handle("POST /groups/new", user(s.groupRequest))
	mux.Handle("GET /groups/{name}", user(s.group))
	mux.Handle("POST /groups/{name}/join", user(s.joinGroup))
	mux.Handle("POST /groups/{name}/leave", user(s.leaveGroup))
	mux.Handle("POST /groups/{name}/members", user(s.groupMembers))
	mux.Handle("POST /groups/{name}/join-requests/{id}", user(s.decideJoin))
	mux.Handle("POST /groups/{name}/description", user(s.groupDescription))
	mux.Handle("POST /groups/{name}/owners", s.require(roleModerator, s.groupOwners))
	mux.Handle("POST /groups/{name}/delete", s.require(roleModerator, s.deleteGroup))
	mux.Handle("POST /groups/{name}/release", s.require(roleModerator, s.releaseGroup))

	// moderators
	mod := func(h http.HandlerFunc) http.Handler { return s.require(roleModerator, h) }
	mux.Handle("GET /mod", mod(s.modHome))
	mux.Handle("GET /mod/accounts", mod(s.modAccounts))
	mux.Handle("POST /mod/accounts/{id}", mod(s.decideAccount))
	mux.Handle("GET /mod/group-requests", mod(s.modGroupRequests))
	mux.Handle("POST /mod/group-requests/{id}", mod(s.decideGroupRequest))
	mux.Handle("GET /mod/groups", mod(s.modGroups))
	mux.Handle("POST /mod/groups/adopt", mod(s.adoptGroup))
	mux.Handle("GET /mod/users", mod(s.modUsers))
	mux.Handle("GET /mod/users/{username}", mod(s.modUser))
	mux.Handle("POST /mod/users/{username}/force-reset", mod(s.forceReset))

	// moderators and administrators
	mux.Handle("GET /activity", s.require(roleModOrAdmin, s.activity))

	// administrators
	adm := func(h http.HandlerFunc) http.Handler { return s.require(roleAdmin, h) }
	mux.Handle("GET /admin", adm(s.admin))
	mux.Handle("POST /admin/settings", adm(s.saveSettings))
	mux.Handle("POST /admin/test/{what}", adm(s.adminTest))

	return s.recoverer(s.securityHeaders(s.withSession(s.csrf(mux))))
}

func staticHandler(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=3600")
		h.ServeHTTP(w, r)
	})
}

func (s *Server) readyz(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	if err := s.store.Ping(ctx); err != nil {
		http.Error(w, "database unavailable", http.StatusServiceUnavailable)
		return
	}
	w.Write([]byte("ready\n"))
}

// clientIP is the peer address, or the forwarded client when the peer is a trusted proxy.
func (s *Server) clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	peer, err := netip.ParseAddr(host)
	if err != nil || !s.trusted(peer) {
		return host
	}
	// Walk X-Forwarded-For from the right, skipping trusted hops.
	parts := strings.Split(r.Header.Get("X-Forwarded-For"), ",")
	for i := len(parts) - 1; i >= 0; i-- {
		a, err := netip.ParseAddr(strings.TrimSpace(parts[i]))
		if err != nil {
			break
		}
		if !s.trusted(a) {
			return a.String()
		}
		host = a.String()
	}
	return host
}

func (s *Server) trusted(a netip.Addr) bool {
	a = a.Unmap()
	for _, p := range s.cfg.TrustedProxies {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// ---- rate limiting ----

type limiter struct {
	mu   sync.Mutex
	hits map[string]*window
}

type window struct {
	n     int
	reset time.Time
}

func newLimiter() *limiter { return &limiter{hits: map[string]*window{}} }

// allow counts one hit for key and reports whether it is within n per period.
func (l *limiter) allow(key string, n int, period time.Duration) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	if len(l.hits) > 10000 {
		for k, w := range l.hits {
			if now.After(w.reset) {
				delete(l.hits, k)
			}
		}
	}
	w, ok := l.hits[key]
	if !ok || now.After(w.reset) {
		w = &window{reset: now.Add(period)}
		l.hits[key] = w
	}
	w.n++
	return w.n <= n
}
