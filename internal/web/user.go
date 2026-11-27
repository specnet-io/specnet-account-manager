package web

import (
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/specnet-io/specnet-account-manager/internal/directory"
	"github.com/specnet-io/specnet-account-manager/internal/notify"
	"github.com/specnet-io/specnet-account-manager/internal/secret"
	"github.com/specnet-io/specnet-account-manager/internal/store"
)

// currentUser loads the signed-in user's directory entry, rendering an error page on failure.
func (s *Server) currentUser(w http.ResponseWriter, r *http.Request) (directory.Directory, *directory.User, bool) {
	dir, err := s.Dir()
	if err != nil {
		s.fail(w, r, http.StatusServiceUnavailable, "The directory is not configured.")
		return nil, nil, false
	}
	u, err := dir.GetUser(r.Context(), sessionFrom(r).Username)
	if err != nil {
		s.log.Error("load user", "err", err)
		s.fail(w, r, http.StatusBadGateway, "Your account could not be loaded from the directory.")
		return nil, nil, false
	}
	return dir, u, true
}

type fieldView struct {
	Key, Label, Value string
	Editable          bool
}

func (s *Server) profile(w http.ResponseWriter, r *http.Request) {
	_, u, ok := s.currentUser(w, r)
	if !ok {
		return
	}
	p := s.page(w, r, "Profile", "profile")
	s.fillProfile(p, u)
	s.render(w, r, http.StatusOK, "profile", p)
}

func (s *Server) fillProfile(p *Page, u *directory.User) {
	editable := map[string]bool{}
	for _, f := range s.settings.List("editable_fields") {
		editable[f] = true
	}
	var fields []fieldView
	for _, f := range directory.ContactFields {
		fields = append(fields, fieldView{Key: f.Key, Label: f.Label, Value: u.Contact.Get(f.Key), Editable: editable[f.Key]})
	}
	p.Data["User"] = u
	p.Data["Fields"] = fields
	p.Data["Gravatar"] = s.settings.Bool("gravatar_enabled")
}

var phoneRE = regexp.MustCompile(`^[0-9+()./ x-]{0,32}$`)

func (s *Server) updateProfile(w http.ResponseWriter, r *http.Request) {
	dir, u, ok := s.currentUser(w, r)
	if !ok {
		return
	}
	c := u.Contact
	newEmail := ""
	for _, f := range s.settings.List("editable_fields") {
		v := clean(r.PostFormValue(f), 128)
		switch f {
		case "email":
			if !strings.EqualFold(v, u.Email) {
				if err := checkEmail(v); err != nil {
					s.back(w, r, "/profile", upperFirst(err.Error())+".", true)
					return
				}
				newEmail = v
			}
			continue
		case "phone", "mobile":
			if !phoneRE.MatchString(v) {
				s.back(w, r, "/profile", "Phone numbers may only contain digits, spaces and + ( ) . - x", true)
				return
			}
		case "surname":
			if v == "" {
				s.back(w, r, "/profile", "Last name is required.", true)
				return
			}
		}
		c.Set(f, v)
	}
	if c != u.Contact {
		if err := dir.UpdateContact(r.Context(), u.Username, c); err != nil {
			s.log.Warn("update contact", "user", u.Username, "err", err)
			s.back(w, r, "/profile", userFacing(err), true)
			return
		}
		s.audit(r, "profile.updated", u.Username, "")
	}
	msg := "Profile saved."
	if newEmail != "" {
		if other, err := dir.FindUserByEmail(r.Context(), newEmail); err == nil && other.Username != u.Username {
			s.back(w, r, "/profile", "That email address belongs to another account.", true)
			return
		}
		tok := secret.Token()
		if err := s.store.PutToken(r.Context(), &store.Token{Hash: secret.Hash(tok), Purpose: store.PurposeEmailChange, Subject: u.Username,
			Data: s.sealer.SealString(newEmail, "email-change:"+u.Username), ExpiresAt: time.Now().Add(emailChangeTTL)}, true); err != nil {
			s.back(w, r, "/profile", "Something went wrong. Try again.", true)
			return
		}
		s.notifier.Notify(r.Context(), "email_change_verify", []string{newEmail}, notify.Data{
			"Name": u.Name(), "Username": u.Username, "NewEmail": newEmail, "Link": s.link("/confirm-email", url.Values{"t": {tok}}), "Hours": int(emailChangeTTL.Hours()),
		})
		s.audit(r, "profile.email_change_requested", u.Username, newEmail)
		msg = "Profile saved. We sent a link to " + newEmail + ": your email address changes once you open it."
	}
	s.back(w, r, "/profile", msg, false)
}

// ---- password ----

func (s *Server) passwordForm(w http.ResponseWriter, r *http.Request) {
	p := s.page(w, r, "Change password", "password")
	p.Data["MinLength"] = s.settings.Int("password_min_length")
	s.render(w, r, http.StatusOK, "password", p)
}

func (s *Server) changePassword(w http.ResponseWriter, r *http.Request) {
	se := sessionFrom(r)
	p := s.page(w, r, "Change password", "password")
	p.Data["MinLength"] = s.settings.Int("password_min_length")
	again := func(status int, msg string) {
		p.Error = msg
		s.render(w, r, status, "password", p)
	}
	if !s.limiter.allow("chpw:"+se.Username, 10, 15*time.Minute) {
		again(http.StatusTooManyRequests, "Too many attempts. Try again later.")
		return
	}
	pw := r.PostFormValue("password")
	if err := s.checkNewPassword(pw, r.PostFormValue("confirm"), se.Username); err != nil {
		again(http.StatusUnprocessableEntity, upperFirst(err.Error())+".")
		return
	}
	dir, u, ok := s.currentUser(w, r)
	if !ok {
		return
	}
	if err := dir.ChangePassword(r.Context(), u.Username, r.PostFormValue("current"), pw); err != nil {
		s.log.Warn("change password", "user", u.Username, "err", err)
		again(http.StatusUnprocessableEntity, userFacing(err))
		return
	}
	s.audit(r, "password.changed", u.Username, "")
	s.notifier.Notify(r.Context(), "password_changed", []string{u.Email}, notify.Data{"Name": u.Name(), "Username": u.Username})
	s.back(w, r, "/password", "Password changed.", false)
}

// ---- SSH keys ----

func (s *Server) keys(w http.ResponseWriter, r *http.Request) {
	_, u, ok := s.currentUser(w, r)
	if !ok {
		return
	}
	p := s.page(w, r, "SSH keys", "keys")
	var keys []*directory.SSHKey
	for _, k := range u.SSHKeys {
		keys = append(keys, directory.DescribeSSHKey(k))
	}
	p.Data["Keys"] = keys
	p.Data["Types"] = s.settings.List("ssh_key_types")
	p.Data["RSAMin"] = s.settings.Int("ssh_rsa_min_bits")
	p.Data["Max"] = s.settings.Int("ssh_max_keys")
	s.render(w, r, http.StatusOK, "keys", p)
}

func (s *Server) addKey(w http.ResponseWriter, r *http.Request) {
	dir, u, ok := s.currentUser(w, r)
	if !ok {
		return
	}
	k, err := directory.ParseSSHKey(r.PostFormValue("key"), s.settings.List("ssh_key_types"), s.settings.Int("ssh_rsa_min_bits"))
	if err != nil {
		s.back(w, r, "/keys", upperFirst(err.Error())+".", true)
		return
	}
	if len(u.SSHKeys) >= s.settings.Int("ssh_max_keys") {
		s.back(w, r, "/keys", "You already have the maximum number of keys. Remove one first.", true)
		return
	}
	for _, existing := range u.SSHKeys {
		if directory.DescribeSSHKey(existing).Fingerprint == k.Fingerprint {
			s.back(w, r, "/keys", "That key is already on your account.", true)
			return
		}
	}
	if err := dir.SetSSHKeys(r.Context(), u.Username, append(append([]string{}, u.SSHKeys...), k.Line)); err != nil {
		s.log.Warn("add ssh key", "user", u.Username, "err", err)
		s.back(w, r, "/keys", userFacing(err), true)
		return
	}
	s.audit(r, "ssh_key.added", u.Username, k.Type+" "+k.Fingerprint)
	s.notifier.Notify(r.Context(), "ssh_key_added", []string{u.Email}, notify.Data{"Name": u.Name(), "Username": u.Username, "KeyType": k.Type, "Fingerprint": k.Fingerprint, "Comment": k.Comment})
	s.back(w, r, "/keys", "Key added.", false)
}

func (s *Server) deleteKey(w http.ResponseWriter, r *http.Request) {
	dir, u, ok := s.currentUser(w, r)
	if !ok {
		return
	}
	fp := r.PostFormValue("fingerprint")
	var keep []string
	var removed *directory.SSHKey
	for _, k := range u.SSHKeys {
		if d := directory.DescribeSSHKey(k); d.Fingerprint == fp && removed == nil {
			removed = d
			continue
		}
		keep = append(keep, k)
	}
	if removed == nil {
		s.back(w, r, "/keys", "That key is not on your account.", true)
		return
	}
	if err := dir.SetSSHKeys(r.Context(), u.Username, keep); err != nil {
		s.back(w, r, "/keys", userFacing(err), true)
		return
	}
	s.audit(r, "ssh_key.removed", u.Username, removed.Type+" "+removed.Fingerprint)
	s.notifier.Notify(r.Context(), "ssh_key_removed", []string{u.Email}, notify.Data{"Name": u.Name(), "Username": u.Username, "KeyType": removed.Type, "Fingerprint": removed.Fingerprint, "Comment": removed.Comment})
	s.back(w, r, "/keys", "Key removed.", false)
}
