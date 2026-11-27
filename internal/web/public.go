package web

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/mail"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/specnet-io/specnet-account-manager/internal/auth"
	"github.com/specnet-io/specnet-account-manager/internal/directory"
	"github.com/specnet-io/specnet-account-manager/internal/notify"
	"github.com/specnet-io/specnet-account-manager/internal/secret"
	"github.com/specnet-io/specnet-account-manager/internal/store"
)

// Token lifetimes. See DETAILS.md §Tokens.
const (
	verifyTTL      = 24 * time.Hour
	resetTTL       = time.Hour
	setupTTL       = 72 * time.Hour
	emailChangeTTL = 24 * time.Hour
	oidcStateTTL   = 10 * time.Minute
)

func (s *Server) home(w http.ResponseWriter, r *http.Request) {
	if se := sessionFrom(r); se != nil {
		switch {
		case se.HasRole(RoleUser):
			http.Redirect(w, r, "/profile", http.StatusSeeOther)
		case se.HasRole(RoleAdmin):
			http.Redirect(w, r, "/admin", http.StatusSeeOther)
		}
		return
	}
	p := s.page(w, r, "Welcome", "home")
	p.Data["SSO"] = s.oidc.Configured()
	s.render(w, r, http.StatusOK, "home", p)
}

// ---- OIDC sign-in ----

type oidcState struct {
	State    string `json:"s"`
	Nonce    string `json:"n"`
	Verifier string `json:"v"`
	Next     string `json:"x"`
	Expires  int64  `json:"e"`
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	if !s.oidc.Configured() {
		s.fail(w, r, http.StatusServiceUnavailable, "Single sign-on is not configured yet. An administrator can sign in with a setup link (sam admin-link) and configure it.")
		return
	}
	st := oidcState{State: secret.Token(), Nonce: secret.Token(), Verifier: secret.Token() + secret.Token()[:22],
		Next: safeNext(r.URL.Query().Get("next")), Expires: time.Now().Add(oidcStateTTL).Unix()}
	to, err := s.oidc.AuthCodeURL(r.Context(), st.State, st.Nonce, st.Verifier)
	if err != nil {
		s.log.Error("oidc", "err", err)
		s.fail(w, r, http.StatusBadGateway, "The sign-in provider is not reachable right now. Try again shortly.")
		return
	}
	b, _ := json.Marshal(st)
	s.setCookie(w, "sam_oidc", s.sealer.Seal(b, "oidc-state"), oidcStateTTL)
	http.Redirect(w, r, to, http.StatusFound)
}

func (s *Server) callback(w http.ResponseWriter, r *http.Request) {
	raw := s.cookie(r, "sam_oidc")
	s.setCookie(w, "sam_oidc", "", -1)
	var st oidcState
	b, err := s.sealer.Open(raw, "oidc-state")
	if err != nil || json.Unmarshal(b, &st) != nil || time.Now().Unix() > st.Expires {
		s.fail(w, r, http.StatusBadRequest, "The sign-in attempt expired. Start again from the sign-in button.")
		return
	}
	q := r.URL.Query()
	if e := q.Get("error"); e != "" {
		s.fail(w, r, http.StatusUnauthorized, "The sign-in provider refused the sign-in: "+e)
		return
	}
	if !secret.Equal(q.Get("state"), st.State) {
		s.fail(w, r, http.StatusBadRequest, "The sign-in attempt did not match. Start again from the sign-in button.")
		return
	}
	id, err := s.oidc.Exchange(r.Context(), q.Get("code"), st.Verifier, st.Nonce)
	if err != nil {
		s.log.Warn("oidc exchange failed", "err", err)
		if errors.Is(err, auth.ErrNotConfigured) {
			s.fail(w, r, http.StatusServiceUnavailable, err.Error())
			return
		}
		s.fail(w, r, http.StatusUnauthorized, "Sign-in failed. Try again, and contact support if it keeps happening.")
		return
	}
	dir, err := s.Dir()
	if err != nil {
		s.fail(w, r, http.StatusServiceUnavailable, "The directory is not configured yet.")
		return
	}
	var u *directory.User
	if s.settings.Get("oidc_match_attribute") == "email" {
		u, err = dir.FindUserByEmail(r.Context(), id.Claim)
	} else {
		u, err = dir.GetUser(r.Context(), id.Claim)
	}
	if errors.Is(err, directory.ErrNotFound) {
		s.auditAs(r, id.Claim, "login.unknown", id.Claim, "signed in at the provider but has no directory account")
		p := s.page(w, r, "No account", "")
		p.Data["Claim"] = id.Claim
		s.render(w, r, http.StatusForbidden, "no_account", p)
		return
	}
	if err != nil {
		s.log.Error("directory lookup at sign-in", "err", err)
		s.fail(w, r, http.StatusBadGateway, "The directory is not reachable right now. Try again shortly.")
		return
	}
	if u.Disabled {
		s.auditAs(r, u.Username, "login.denied", u.Username, "account disabled")
		s.fail(w, r, http.StatusForbidden, "This account is disabled.")
		return
	}
	roles, err := s.rolesFor(r.Context(), dir, u.Username)
	if err != nil {
		s.fail(w, r, http.StatusBadGateway, "The directory is not reachable right now. Try again shortly.")
		return
	}
	if err := s.startSession(w, r, u.Username, u.Name(), u.Email, roles, time.Duration(s.settings.Int("session_hours"))*time.Hour); err != nil {
		s.fail(w, r, http.StatusInternalServerError, "Could not start a session.")
		return
	}
	s.auditAs(r, u.Username, "login", u.Username, "roles: "+strings.Join(roles, ","))
	http.Redirect(w, r, safeNext(st.Next), http.StatusSeeOther)
}

func (s *Server) startSession(w http.ResponseWriter, r *http.Request, username, name, email string, roles []string, ttl time.Duration) error {
	if old := s.cookie(r, "sam_session"); old != "" {
		_ = s.store.DeleteSession(r.Context(), secret.Hash(old))
	}
	tok := secret.Token()
	now := time.Now()
	se := &store.Session{IDHash: secret.Hash(tok), Username: username, DisplayName: name, Email: email, Roles: roles,
		CSRF: secret.Token(), CreatedAt: now, ExpiresAt: now.Add(ttl), RefreshedAt: now}
	if err := s.store.CreateSession(r.Context(), se); err != nil {
		s.log.Error("create session", "err", err)
		return err
	}
	s.setCookie(w, "sam_session", tok, 0)
	return nil
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if tok := s.cookie(r, "sam_session"); tok != "" {
		_ = s.store.DeleteSession(r.Context(), secret.Hash(tok))
	}
	s.setCookie(w, "sam_session", "", -1)
	s.back(w, r, "/", "You are signed out of this site. Your single sign-on session may still be active.", false)
}

// ---- account requests ----

func (s *Server) requestAccountForm(w http.ResponseWriter, r *http.Request) {
	if !s.settings.Bool("account_requests_enabled") {
		s.fail(w, r, http.StatusNotFound, "Account requests are closed.")
		return
	}
	p := s.page(w, r, "Request an account", "request")
	p.Form = url.Values{}
	s.render(w, r, http.StatusOK, "request_account", p)
}

func (s *Server) requestAccount(w http.ResponseWriter, r *http.Request) {
	if !s.settings.Bool("account_requests_enabled") {
		s.fail(w, r, http.StatusNotFound, "Account requests are closed.")
		return
	}
	p := s.page(w, r, "Request an account", "request")
	p.Form = r.PostForm
	again := func(msg string) {
		p.Error = msg
		s.render(w, r, http.StatusUnprocessableEntity, "request_account", p)
	}
	if !s.limiter.allow("request:"+s.clientIP(r), 5, time.Hour) {
		again("Too many requests from your network. Try again later.")
		return
	}
	req := &store.AccountRequest{
		Username:      strings.ToLower(strings.TrimSpace(r.PostFormValue("username"))),
		GivenName:     clean(r.PostFormValue("given_name"), 64),
		Surname:       clean(r.PostFormValue("surname"), 64),
		Email:         strings.TrimSpace(r.PostFormValue("email")),
		Justification: cleanText(r.PostFormValue("justification"), 2000),
		Status:        store.StatusUnverified,
	}
	if err := s.checkUsername(req.Username); err != nil {
		again(err.Error())
		return
	}
	if req.GivenName == "" || req.Surname == "" {
		again("First and last name are required.")
		return
	}
	if err := checkEmail(req.Email); err != nil {
		again(err.Error())
		return
	}
	if req.Justification == "" {
		again("Tell the moderators why you need an account.")
		return
	}
	dir, err := s.Dir()
	if err != nil {
		again("Account requests are not available yet (the directory is not configured).")
		return
	}
	if _, err := dir.GetUser(r.Context(), req.Username); err == nil {
		again("That username is taken. Choose another.")
		return
	} else if !errors.Is(err, directory.ErrNotFound) {
		s.log.Error("directory", "err", err)
		again("The directory is not reachable right now. Try again shortly.")
		return
	}
	open, err := s.store.OpenAccountRequestFor(r.Context(), req.Username, req.Email)
	if err != nil {
		again("Something went wrong. Try again.")
		return
	}
	if open {
		again("A request for that username or email address is already waiting.")
		return
	}
	// An existing account with this email gets the same "check your inbox" answer, not a hint.
	if _, err := dir.FindUserByEmail(r.Context(), req.Email); err == nil {
		s.auditAs(r, "anonymous", "account_request.duplicate_email", req.Username, "")
		s.render(w, r, http.StatusOK, "request_sent", p)
		return
	}
	if err := s.store.CreateAccountRequest(r.Context(), req); err != nil {
		s.log.Error("create request", "err", err)
		again("Something went wrong. Try again.")
		return
	}
	tok := secret.Token()
	if err := s.store.PutToken(r.Context(), &store.Token{Hash: secret.Hash(tok), Purpose: store.PurposeVerifyRequest, Subject: req.ID, ExpiresAt: time.Now().Add(verifyTTL)}, true); err != nil {
		again("Something went wrong. Try again.")
		return
	}
	s.notifier.Notify(r.Context(), "verify_request", []string{req.Email}, notify.Data{
		"Name": req.GivenName, "Username": req.Username, "Link": s.link("/verify", url.Values{"t": {tok}}), "Hours": int(verifyTTL.Hours()),
	})
	s.auditAs(r, "anonymous", "account_request.created", req.Username, req.Email)
	s.render(w, r, http.StatusOK, "request_sent", p)
}

// tokenConfirmPage shows a button that POSTs the token back: email scanners prefetch GET links.
func (s *Server) tokenConfirmPage(kind, purpose string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tok := r.URL.Query().Get("t")
		if _, err := s.store.PeekToken(r.Context(), secret.Hash(tok), purpose); err != nil {
			s.fail(w, r, http.StatusNotFound, "This link is invalid, already used or expired.")
			return
		}
		p := s.page(w, r, "Confirm", "")
		p.Data["Token"] = tok
		p.Data["Kind"] = kind
		s.render(w, r, http.StatusOK, "confirm", p)
	}
}

func (s *Server) verifyRequest(w http.ResponseWriter, r *http.Request) {
	t, err := s.store.TakeToken(r.Context(), secret.Hash(r.PostFormValue("t")), store.PurposeVerifyRequest)
	if err != nil {
		s.fail(w, r, http.StatusNotFound, "This link is invalid, already used or expired.")
		return
	}
	req, err := s.store.GetAccountRequest(r.Context(), t.Subject)
	if err != nil || s.store.SetAccountRequestStatus(r.Context(), req.ID, store.StatusUnverified, store.StatusPending, "", "") != nil {
		s.fail(w, r, http.StatusNotFound, "This request is no longer waiting for confirmation.")
		return
	}
	s.auditAs(r, "anonymous", "account_request.verified", req.Username, req.Email)
	if dir, err := s.Dir(); err == nil {
		s.notifier.Notify(r.Context(), "moderators_new_account", s.moderatorEmails(r.Context(), dir), notify.Data{
			"Name": req.GivenName + " " + req.Surname, "Email": req.Email, "Username": req.Username,
			"Justification": req.Justification, "Link": s.link("/mod/accounts", nil),
		})
	}
	p := s.page(w, r, "Request confirmed", "")
	p.Data["Message"] = "Thanks, your email address is confirmed. A moderator will review your request and you will get an email when it is decided."
	s.render(w, r, http.StatusOK, "message", p)
}

// ---- forgotten passwords ----

func (s *Server) forgotForm(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, http.StatusOK, "forgot", s.page(w, r, "Forgot password", "forgot"))
}

func (s *Server) forgot(w http.ResponseWriter, r *http.Request) {
	p := s.page(w, r, "Forgot password", "forgot")
	who := strings.TrimSpace(r.PostFormValue("who"))
	if who == "" {
		p.Error = "Enter your username or email address."
		s.render(w, r, http.StatusUnprocessableEntity, "forgot", p)
		return
	}
	if !s.limiter.allow("forgot:"+s.clientIP(r), 5, 15*time.Minute) || !s.limiter.allow("forgot:"+strings.ToLower(who), 3, time.Hour) {
		p.Error = "Too many attempts. Try again later."
		s.render(w, r, http.StatusTooManyRequests, "forgot", p)
		return
	}
	p.Data["Sent"] = true
	dir, err := s.Dir()
	if err != nil {
		s.render(w, r, http.StatusOK, "forgot", p)
		return
	}
	var u *directory.User
	if strings.Contains(who, "@") {
		u, err = dir.FindUserByEmail(r.Context(), who)
	} else {
		u, err = dir.GetUser(r.Context(), strings.ToLower(who))
	}
	// Same answer whether or not the account exists.
	if err == nil && !u.Disabled && u.Email != "" {
		s.sendPasswordLink(r, u, "password_reset", resetTTL, nil)
		s.auditAs(r, "anonymous", "password.reset_requested", u.Username, "")
	}
	s.render(w, r, http.StatusOK, "forgot", p)
}

func (s *Server) sendPasswordLink(r *http.Request, u *directory.User, event string, ttl time.Duration, extra notify.Data) {
	tok := secret.Token()
	if err := s.store.PutToken(r.Context(), &store.Token{Hash: secret.Hash(tok), Purpose: store.PurposePassword, Subject: u.Username, ExpiresAt: time.Now().Add(ttl)}, true); err != nil {
		s.log.Error("store token", "err", err)
		return
	}
	data := notify.Data{"Name": u.Name(), "Username": u.Username, "Link": s.link("/reset-password", url.Values{"t": {tok}}), "Hours": int(ttl.Hours())}
	for k, v := range extra {
		data[k] = v
	}
	s.notifier.Notify(r.Context(), event, []string{u.Email}, data)
}

func (s *Server) resetForm(w http.ResponseWriter, r *http.Request) {
	tok := r.URL.Query().Get("t")
	t, err := s.store.PeekToken(r.Context(), secret.Hash(tok), store.PurposePassword)
	if err != nil {
		s.fail(w, r, http.StatusNotFound, "This link is invalid, already used or expired. Ask for a new one from \"Forgot password\".")
		return
	}
	p := s.page(w, r, "Choose a password", "")
	p.Data["Token"] = tok
	p.Data["Username"] = t.Subject
	p.Data["MinLength"] = s.settings.Int("password_min_length")
	s.render(w, r, http.StatusOK, "reset", p)
}

func (s *Server) reset(w http.ResponseWriter, r *http.Request) {
	tok := r.PostFormValue("t")
	t, err := s.store.PeekToken(r.Context(), secret.Hash(tok), store.PurposePassword)
	if err != nil {
		s.fail(w, r, http.StatusNotFound, "This link is invalid, already used or expired.")
		return
	}
	p := s.page(w, r, "Choose a password", "")
	p.Data["Token"] = tok
	p.Data["Username"] = t.Subject
	p.Data["MinLength"] = s.settings.Int("password_min_length")
	pw := r.PostFormValue("password")
	if err := s.checkNewPassword(pw, r.PostFormValue("confirm"), t.Subject); err != nil {
		p.Error = err.Error()
		s.render(w, r, http.StatusUnprocessableEntity, "reset", p)
		return
	}
	if !s.limiter.allow("reset:"+t.Subject, 10, time.Hour) {
		p.Error = "Too many attempts. Try again later."
		s.render(w, r, http.StatusTooManyRequests, "reset", p)
		return
	}
	dir, err := s.Dir()
	if err != nil {
		s.fail(w, r, http.StatusServiceUnavailable, "The directory is not configured.")
		return
	}
	if err := dir.SetPassword(r.Context(), t.Subject, pw); err != nil {
		s.log.Warn("set password", "user", t.Subject, "err", err)
		p.Error = userFacing(err)
		s.render(w, r, http.StatusUnprocessableEntity, "reset", p)
		return
	}
	_, _ = s.store.TakeToken(r.Context(), t.Hash, store.PurposePassword)
	_ = s.store.DeleteTokens(r.Context(), store.PurposePassword, t.Subject)
	s.auditAs(r, t.Subject, "password.reset", t.Subject, "via emailed link")
	if u, err := dir.GetUser(r.Context(), t.Subject); err == nil {
		s.notifier.Notify(r.Context(), "password_changed", []string{u.Email}, notify.Data{"Name": u.Name(), "Username": u.Username})
	}
	mp := s.page(w, r, "Password set", "")
	mp.Data["Message"] = "Your password is set. You can now sign in."
	mp.Data["SignIn"] = true
	s.render(w, r, http.StatusOK, "message", mp)
}

// ---- email change confirmation ----

func (s *Server) confirmEmail(w http.ResponseWriter, r *http.Request) {
	t, err := s.store.TakeToken(r.Context(), secret.Hash(r.PostFormValue("t")), store.PurposeEmailChange)
	if err != nil {
		s.fail(w, r, http.StatusNotFound, "This link is invalid, already used or expired.")
		return
	}
	newEmail, err := s.sealer.OpenString(t.Data, "email-change:"+t.Subject)
	if err != nil {
		s.fail(w, r, http.StatusBadRequest, "This link cannot be used.")
		return
	}
	dir, err := s.Dir()
	if err != nil {
		s.fail(w, r, http.StatusServiceUnavailable, "The directory is not configured.")
		return
	}
	u, err := dir.GetUser(r.Context(), t.Subject)
	if err != nil {
		s.fail(w, r, http.StatusNotFound, "The account no longer exists.")
		return
	}
	old := u.Email
	c := u.Contact
	c.Email = newEmail
	if err := dir.UpdateContact(r.Context(), u.Username, c); err != nil {
		s.fail(w, r, http.StatusBadGateway, userFacing(err))
		return
	}
	s.auditAs(r, u.Username, "profile.email_changed", u.Username, old+" -> "+newEmail)
	s.notifier.Notify(r.Context(), "email_changed_notice", []string{old}, notify.Data{"Name": u.Name(), "Username": u.Username, "NewEmail": newEmail})
	p := s.page(w, r, "Email confirmed", "")
	p.Data["Message"] = "Your email address is now " + newEmail + "."
	s.render(w, r, http.StatusOK, "message", p)
}

// ---- bootstrap admin link ----

func (s *Server) adminLink(w http.ResponseWriter, r *http.Request) {
	if _, err := s.store.TakeToken(r.Context(), secret.Hash(r.PostFormValue("t")), store.PurposeAdminLink); err != nil {
		s.fail(w, r, http.StatusNotFound, "This link is invalid, already used or expired. Run `sam admin-link` again.")
		return
	}
	if err := s.startSession(w, r, "", "Setup administrator", "", []string{RoleAdmin}, time.Hour); err != nil {
		s.fail(w, r, http.StatusInternalServerError, "Could not start a session.")
		return
	}
	s.auditAs(r, "(setup admin)", "login.admin_link", "", "one-time setup link used")
	s.back(w, r, "/admin", "Signed in with a one-time setup link for one hour. Configure sign-in and the directory, then sign in normally.", false)
}

// ---- validation helpers ----

func (s *Server) checkUsername(u string) error {
	re, err := regexp.Compile(s.settings.Get("username_pattern"))
	if err != nil {
		return errors.New("the username rule is misconfigured")
	}
	if u == "" || !re.MatchString(u) {
		return errors.New("that username is not allowed: use lower-case letters, digits, dots, dashes or underscores, starting with a letter")
	}
	return nil
}

func (s *Server) checkNewPassword(pw, confirm, username string) error {
	min := s.settings.Int("password_min_length")
	switch {
	case pw != confirm:
		return errors.New("the two passwords do not match")
	case utf8.RuneCountInString(pw) < min:
		return errors.New("the password must be at least " + itoa(min) + " characters")
	case len(pw) > 256:
		return errors.New("the password is too long")
	case username != "" && strings.Contains(strings.ToLower(pw), strings.ToLower(username)):
		return errors.New("the password must not contain your username")
	}
	return nil
}

func checkEmail(e string) error {
	a, err := mail.ParseAddress(e)
	if err != nil || a.Address != e || len(e) > 254 || !strings.Contains(e[strings.LastIndex(e, "@"):], ".") {
		return errors.New("enter a valid email address")
	}
	return nil
}

// clean trims a single-line value, drops control characters and caps the length.
func clean(v string, max int) string {
	v = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, strings.TrimSpace(v))
	if utf8.RuneCountInString(v) > max {
		v = string([]rune(v)[:max])
	}
	return v
}

// cleanText is clean for multi-line text.
func cleanText(v string, max int) string {
	v = strings.Map(func(r rune) rune {
		if (r < 0x20 && r != '\n') || r == 0x7f {
			return -1
		}
		return r
	}, strings.TrimSpace(strings.ReplaceAll(v, "\r\n", "\n")))
	if utf8.RuneCountInString(v) > max {
		v = string([]rune(v)[:max])
	}
	return v
}

// userFacing turns directory errors into messages safe to show.
func userFacing(err error) string {
	for _, known := range []error{directory.ErrInvalidCreds, directory.ErrPasswordPolicy, directory.ErrNotFound, directory.ErrExists, directory.ErrNotConfigured} {
		if errors.Is(err, known) {
			return upperFirst(err.Error()) + "."
		}
	}
	return "The directory could not make this change. Try again, or contact support."
}

func upperFirst(s string) string {
	if s == "" {
		return s
	}
	r := []rune(s)
	return strings.ToUpper(string(r[0])) + string(r[1:])
}

func itoa(n int) string { return strconv.Itoa(n) }
