package web

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"net/url"
	"path"
	"runtime/debug"
	"sort"
	"strings"
	"time"

	"github.com/specnet-io/specnet-account-manager/internal/avatar"
	"github.com/specnet-io/specnet-account-manager/internal/directory"
	"github.com/specnet-io/specnet-account-manager/internal/secret"
	"github.com/specnet-io/specnet-account-manager/internal/store"
)

type ctxKey int

const (
	keySession ctxKey = iota
	keyCSRF
)

type role int

const (
	roleUser role = iota
	roleModerator
	roleAdmin
	roleModOrAdmin
)

// Role names stored on sessions.
const (
	RoleUser      = "user"
	RoleModerator = "moderator"
	RoleAdmin     = "admin"
)

// refreshEvery is how often a session's roles are re-read from the directory.
const refreshEvery = 5 * time.Minute

func (s *Server) cookieName(n string) string {
	if s.secure {
		return "__Host-" + n
	}
	return n
}

func (s *Server) setCookie(w http.ResponseWriter, name, value string, maxAge time.Duration) {
	c := &http.Cookie{Name: s.cookieName(name), Value: value, Path: "/", HttpOnly: true, Secure: s.secure, SameSite: http.SameSiteLaxMode}
	if maxAge < 0 {
		c.MaxAge = -1
	} else if maxAge > 0 {
		c.MaxAge = int(maxAge.Seconds())
	}
	http.SetCookie(w, c)
}

func (s *Server) cookie(r *http.Request, name string) string {
	c, err := r.Cookie(s.cookieName(name))
	if err != nil {
		return ""
	}
	return c.Value
}

func (s *Server) recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if v := recover(); v != nil {
				if v == http.ErrAbortHandler {
					panic(v)
				}
				s.log.Error("panic", "path", r.URL.Path, "err", v, "stack", string(debug.Stack()))
				http.Error(w, "internal error", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'none'; style-src 'self'; img-src 'self' https://gravatar.com https://www.gravatar.com https://secure.gravatar.com; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer") // pages carry one-time tokens in the URL
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		if s.secure {
			h.Set("Strict-Transport-Security", "max-age=31536000")
		}
		if !strings.HasPrefix(r.URL.Path, "/static/") {
			h.Set("Cache-Control", "no-store")
		}
		r.Body = http.MaxBytesReader(w, r.Body, 256<<10)
		next.ServeHTTP(w, r)
	})
}

// withSession loads the session (if any), refreshing its roles from the directory every few minutes.
func (s *Server) withSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/static/") || r.URL.Path == "/healthz" || r.URL.Path == "/readyz" {
			next.ServeHTTP(w, r)
			return
		}
		if tok := s.cookie(r, "sam_session"); tok != "" {
			se, err := s.store.GetSession(r.Context(), secret.Hash(tok))
			if err == nil && se.Username != "" && time.Since(se.RefreshedAt) > refreshEvery {
				if !s.refreshSession(r.Context(), se) {
					_ = s.store.DeleteSession(r.Context(), se.IDHash)
					se = nil
				}
			}
			if err == nil && se != nil {
				r = r.WithContext(context.WithValue(r.Context(), keySession, se))
			}
		}
		next.ServeHTTP(w, r)
	})
}

// refreshSession re-reads identity and roles; false means the account is gone or disabled.
func (s *Server) refreshSession(ctx context.Context, se *store.Session) bool {
	dir, err := s.Dir()
	if err != nil {
		return true // keep the session on configuration/transient errors; roles stay as they were
	}
	u, err := dir.GetUser(ctx, se.Username)
	if errors.Is(err, directory.ErrNotFound) {
		return false
	}
	if err != nil {
		s.log.Warn("session refresh failed", "user", se.Username, "err", err)
		return true
	}
	if u.Disabled {
		return false
	}
	roles, err := s.rolesFor(ctx, dir, u.Username)
	if err != nil {
		s.log.Warn("session role refresh failed", "user", se.Username, "err", err)
		return true
	}
	se.DisplayName, se.Email, se.Roles, se.RefreshedAt = u.Name(), u.Email, roles, time.Now()
	if err := s.store.RefreshSession(ctx, se); err != nil {
		s.log.Warn("session update failed", "err", err)
	}
	return true
}

func (s *Server) rolesFor(ctx context.Context, dir directory.Directory, username string) ([]string, error) {
	groups, err := dir.UserGroups(ctx, username)
	if err != nil {
		return nil, err
	}
	roles := []string{RoleUser}
	mg, ag := s.settings.Get("moderator_group"), s.settings.Get("admin_group")
	for _, g := range groups {
		if mg != "" && strings.EqualFold(g, mg) {
			roles = append(roles, RoleModerator)
		}
		if ag != "" && strings.EqualFold(g, ag) {
			roles = append(roles, RoleAdmin)
		}
	}
	return roles, nil
}

func sessionFrom(r *http.Request) *store.Session {
	se, _ := r.Context().Value(keySession).(*store.Session)
	return se
}

// csrf issues a per-browser token cookie and checks it (plus Origin) on every POST.
func (s *Server) csrf(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok := s.cookie(r, "sam_csrf")
		if se := sessionFrom(r); se != nil {
			tok = se.CSRF
		} else if tok == "" && r.Method == http.MethodGet {
			tok = secret.Token()
			s.setCookie(w, "sam_csrf", tok, 0)
		}
		if r.Method == http.MethodPost {
			if o := r.Header.Get("Origin"); o != "" && o != "null" && !strings.EqualFold(o, s.base.Scheme+"://"+s.base.Host) {
				s.fail(w, r, http.StatusForbidden, "This form was submitted from another site.")
				return
			}
			if tok == "" || !secret.Equal(r.PostFormValue("csrf"), tok) {
				s.fail(w, r, http.StatusForbidden, "Your form expired. Go back, reload the page and try again.")
				return
			}
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), keyCSRF, tok)))
	})
}

func (s *Server) require(need role, h http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		se := sessionFrom(r)
		if se == nil {
			if r.Method == http.MethodGet {
				http.Redirect(w, r, "/login?next="+url.QueryEscape(r.URL.RequestURI()), http.StatusSeeOther)
				return
			}
			s.fail(w, r, http.StatusUnauthorized, "Your session has ended. Sign in again.")
			return
		}
		ok := false
		switch need {
		case roleUser:
			ok = se.HasRole(RoleUser)
		case roleModerator:
			ok = se.HasRole(RoleModerator)
		case roleAdmin:
			ok = se.HasRole(RoleAdmin)
		case roleModOrAdmin:
			ok = se.HasRole(RoleModerator) || se.HasRole(RoleAdmin)
		}
		if !ok {
			s.fail(w, r, http.StatusForbidden, "You do not have access to this page.")
			return
		}
		h(w, r)
	})
}

// ---- rendering ----

var funcs = template.FuncMap{
	"when": func(t time.Time) string {
		if t.IsZero() || t.Unix() == 0 {
			return ""
		}
		return t.UTC().Format("2006-01-02 15:04 UTC")
	},
	"join": strings.Join,
	"has": func(list []string, v string) bool {
		for _, x := range list {
			if strings.EqualFold(x, v) {
				return true
			}
		}
		return false
	},
}

func (s *Server) parseTemplates() error {
	s.pages = map[string]*template.Template{}
	files, err := fs.Glob(assets, "templates/*.html")
	if err != nil {
		return err
	}
	f := template.FuncMap{"avatar": s.avatarURL}
	for k, v := range funcs {
		f[k] = v
	}
	for _, file := range files {
		name := strings.TrimSuffix(path.Base(file), ".html")
		if name == "layout" {
			continue
		}
		t, err := template.New(name).Funcs(f).ParseFS(assets, "templates/layout.html", file)
		if err != nil {
			return fmt.Errorf("template %s: %w", name, err)
		}
		s.pages[name] = t
	}
	return nil
}

func (s *Server) avatarURL(email string, size int) string {
	if !s.settings.Bool("gravatar_enabled") || email == "" {
		return ""
	}
	return avatar.Gravatar(email, size, s.settings.Get("gravatar_default"))
}

// Page is the data every template gets.
type Page struct {
	Title    string
	Nav      string
	Site     string
	Support  string
	Version  string
	Session  *store.Session
	CSRF     string
	Flash    string
	FlashErr bool
	Error    string
	Form     url.Values
	Data     map[string]any
	IsMod    bool
	IsAdmin  bool
	IsUser   bool
	Requests bool
}

type flash struct {
	msg   string
	isErr bool
}

func (s *Server) setFlash(w http.ResponseWriter, msg string, isErr bool) {
	v := "i" + msg
	if isErr {
		v = "e" + msg
	}
	s.setCookie(w, "sam_flash", base64.RawURLEncoding.EncodeToString([]byte(v)), time.Minute)
}

func (s *Server) takeFlash(w http.ResponseWriter, r *http.Request) flash {
	raw := s.cookie(r, "sam_flash")
	if raw == "" {
		return flash{}
	}
	s.setCookie(w, "sam_flash", "", -1)
	b, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil || len(b) < 2 {
		return flash{}
	}
	return flash{msg: string(b[1:]), isErr: b[0] == 'e'}
}

func (s *Server) page(w http.ResponseWriter, r *http.Request, title, nav string) *Page {
	se := sessionFrom(r)
	p := &Page{
		Title: title, Nav: nav, Site: s.settings.Get("site_name"), Support: s.settings.Get("support_email"),
		Version: s.cfg.Version, Session: se, Data: map[string]any{},
		Requests: s.settings.Bool("account_requests_enabled"),
	}
	p.CSRF, _ = r.Context().Value(keyCSRF).(string)
	if se != nil {
		p.IsUser, p.IsMod, p.IsAdmin = se.HasRole(RoleUser), se.HasRole(RoleModerator), se.HasRole(RoleAdmin)
	}
	f := s.takeFlash(w, r)
	p.Flash, p.FlashErr = f.msg, f.isErr
	return p
}

func (s *Server) render(w http.ResponseWriter, r *http.Request, status int, name string, p *Page) {
	t, ok := s.pages[name]
	if !ok {
		s.log.Error("missing template", "name", name)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	var buf bytes.Buffer
	if err := t.ExecuteTemplate(&buf, "layout", p); err != nil {
		s.log.Error("render failed", "template", name, "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = buf.WriteTo(w)
}

func (s *Server) fail(w http.ResponseWriter, r *http.Request, status int, msg string) {
	p := s.page(w, r, http.StatusText(status), "")
	p.Error = msg
	s.render(w, r, status, "error", p)
}

// back redirects to path with a flash message.
func (s *Server) back(w http.ResponseWriter, r *http.Request, to, msg string, isErr bool) {
	if msg != "" {
		s.setFlash(w, msg, isErr)
	}
	http.Redirect(w, r, to, http.StatusSeeOther)
}

func (s *Server) audit(r *http.Request, action, target, detail string) {
	actor := "anonymous"
	if se := sessionFrom(r); se != nil {
		actor = se.Username
		if actor == "" {
			actor = "(setup admin)"
		}
	}
	s.auditAs(r, actor, action, target, detail)
}

func (s *Server) auditAs(r *http.Request, actor, action, target, detail string) {
	if err := s.store.Audit(r.Context(), actor, action, target, detail, s.clientIP(r)); err != nil {
		s.log.Error("audit write failed", "err", err)
	}
	s.log.Info("audit", "actor", actor, "action", action, "target", target, "detail", detail)
}

// link builds an absolute URL under the base URL.
func (s *Server) link(p string, q url.Values) string {
	u := s.cfg.BaseURL + p
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	return u
}

// emailsOf returns the email addresses of the given usernames (skipping unknown/blank).
func (s *Server) emailsOf(ctx context.Context, dir directory.Directory, usernames []string) []string {
	var out []string
	for _, u := range usernames {
		if usr, err := dir.GetUser(ctx, u); err == nil && usr.Email != "" && !usr.Disabled {
			out = append(out, usr.Email)
		}
	}
	return out
}

// moderatorEmails returns the addresses of the moderator group's members.
func (s *Server) moderatorEmails(ctx context.Context, dir directory.Directory) []string {
	g, err := dir.GetGroup(ctx, s.settings.Get("moderator_group"))
	if err != nil {
		s.log.Warn("cannot read moderator group for notifications", "err", err)
		return nil
	}
	return s.emailsOf(ctx, dir, g.Members)
}

// reserved reports whether the name is one of SAM's own role groups. Owners of those could grant themselves
// moderator or admin rights, so SAM never manages them, whatever else is configured.
func (s *Server) reserved(name string) bool {
	n := strings.ToLower(name)
	return n == strings.ToLower(s.settings.Get("moderator_group")) || n == strings.ToLower(s.settings.Get("admin_group"))
}

// fasOnly reports whether SAM manages only FreeIPA FAS groups (ldap_fas_groups). See DETAILS.md §Directory.
func (s *Server) fasOnly() bool {
	return s.settings.Bool("ldap_fas_groups") && s.settings.Get("ldap_profile") == "freeipa"
}

// manageable reports whether SAM may manage this directory group: not reserved, and a FAS group when fasOnly.
func (s *Server) manageable(g *directory.Group) bool {
	return !s.reserved(g.Name) && (!s.fasOnly() || g.FAS)
}

// notManageableMsg explains why manageable refused g.
func (s *Server) notManageableMsg(g *directory.Group) string {
	if s.reserved(g.Name) {
		return g.Name + " is one of SAM's role groups and cannot be managed here."
	}
	return g.Name + " is not a FAS group, so SAM does not manage it."
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// safeNext keeps post-login redirects on this site.
func safeNext(next string) string {
	if next == "" || !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") || strings.HasPrefix(next, "/\\") {
		return "/"
	}
	return next
}
