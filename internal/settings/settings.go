// Package settings is the runtime configuration: defaults, overridden by the admin page (DB), overridden by SAM_* env (locked). See DETAILS.md §Settings.
package settings

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/specnet-io/specnet-account-manager/internal/secret"
	"github.com/specnet-io/specnet-account-manager/internal/store"
)

// Kind is how a setting is edited and validated.
type Kind string

// Setting kinds.
const (
	Text     Kind = "text"
	Secret   Kind = "secret"
	Bool     Kind = "bool"
	Int      Kind = "int"
	Select   Kind = "select"
	TextArea Kind = "textarea"
	List     Kind = "list" // comma separated
)

// Def describes one setting.
type Def struct {
	Key     string
	Section string
	Label   string
	Help    string
	Kind    Kind
	Default string
	Options []string
	Min     int
}

// EnvName is the environment variable that sets (and locks) this setting.
func (d Def) EnvName() string { return "SAM_" + strings.ToUpper(d.Key) }

// Sections in display order.
var Sections = []string{"General", "Roles", "Sign-in (OIDC)", "Directory (LDAP)", "Notifications", "Profile"}

// Defs is the full registry.
var Defs = []Def{
	{Key: "site_name", Section: "General", Label: "Site name", Kind: Text, Default: "Specnet Account Manager"},
	{Key: "support_email", Section: "General", Label: "Support contact", Help: "Shown in the footer and in emails.", Kind: Text},
	{Key: "account_requests_enabled", Section: "General", Label: "Allow account requests", Kind: Bool, Default: "true"},
	{Key: "username_pattern", Section: "General", Label: "Username pattern", Help: "Regular expression new usernames must match.", Kind: Text, Default: `^[a-z][a-z0-9._-]{1,31}$`},
	{Key: "group_name_pattern", Section: "General", Label: "Group name pattern", Kind: Text, Default: `^[a-z][a-z0-9._-]{1,63}$`},
	{Key: "password_min_length", Section: "General", Label: "Minimum password length", Help: "The directory's own policy still applies.", Kind: Int, Default: "12", Min: 8},
	{Key: "session_hours", Section: "General", Label: "Session lifetime (hours)", Kind: Int, Default: "12", Min: 1},
	{Key: "audit_retention_days", Section: "General", Label: "Keep activity log (days)", Help: "0 keeps it forever.", Kind: Int, Default: "365"},

	{Key: "moderator_group", Section: "Roles", Label: "Moderator group", Help: "Directory group whose members approve accounts and manage groups.", Kind: Text, Default: "sam-moderators"},
	{Key: "admin_group", Section: "Roles", Label: "Administrator group", Help: "Directory group whose members manage these settings.", Kind: Text, Default: "sam-admins"},

	{Key: "oidc_issuer", Section: "Sign-in (OIDC)", Label: "Issuer URL", Help: "e.g. https://sso.example.com/realms/main", Kind: Text},
	{Key: "oidc_client_id", Section: "Sign-in (OIDC)", Label: "Client ID", Kind: Text},
	{Key: "oidc_client_secret", Section: "Sign-in (OIDC)", Label: "Client secret", Help: "Leave empty for a public client (PKCE is always used).", Kind: Secret},
	{Key: "oidc_scopes", Section: "Sign-in (OIDC)", Label: "Scopes", Kind: List, Default: "openid,profile,email"},
	{Key: "oidc_username_claim", Section: "Sign-in (OIDC)", Label: "Claim to match", Kind: Text, Default: "preferred_username"},
	{Key: "oidc_match_attribute", Section: "Sign-in (OIDC)", Label: "Match the claim against", Kind: Select, Options: []string{"username", "email"}, Default: "username"},
	{Key: "oidc_strip_domain", Section: "Sign-in (OIDC)", Label: "Strip @domain from the claim", Help: "Turns user@REALM into user before matching usernames.", Kind: Bool, Default: "false"},

	{Key: "ldap_profile", Section: "Directory (LDAP)", Label: "Directory type", Kind: Select, Options: []string{"freeipa", "openldap"}, Default: "freeipa"},
	{Key: "ldap_url", Section: "Directory (LDAP)", Label: "Server URL", Help: "ldaps://host:636 or ldap://host:389 (use StartTLS).", Kind: Text},
	{Key: "ldap_starttls", Section: "Directory (LDAP)", Label: "Use StartTLS on ldap://", Kind: Bool, Default: "true"},
	{Key: "ldap_ca_cert", Section: "Directory (LDAP)", Label: "CA certificate (PEM)", Help: "Empty uses the system trust store.", Kind: TextArea},
	{Key: "ldap_insecure_skip_verify", Section: "Directory (LDAP)", Label: "Skip TLS verification (testing only)", Kind: Bool, Default: "false"},
	{Key: "ldap_bind_dn", Section: "Directory (LDAP)", Label: "Service account DN", Kind: Text},
	{Key: "ldap_bind_password", Section: "Directory (LDAP)", Label: "Service account password", Kind: Secret},
	{Key: "ldap_base_dn", Section: "Directory (LDAP)", Label: "Base DN", Help: "e.g. dc=example,dc=com", Kind: Text},
	{Key: "ldap_user_base", Section: "Directory (LDAP)", Label: "User base", Help: "Empty: cn=users,cn=accounts,<base> (FreeIPA) or ou=people,<base>.", Kind: Text},
	{Key: "ldap_group_base", Section: "Directory (LDAP)", Label: "Group base", Help: "Empty: cn=groups,cn=accounts,<base> (FreeIPA) or ou=groups,<base>.", Kind: Text},
	{Key: "ldap_fas_groups", Section: "Directory (LDAP)", Label: "Only FAS groups (FreeIPA)", Help: "Manage only groups with the fasGroup object class (freeipa-fas); new groups get it. Remove it from a group to take that group out of SAM.", Kind: Bool, Default: "false"},
	{Key: "ldap_kerberos_realm", Section: "Directory (LDAP)", Label: "Kerberos realm (FreeIPA)", Help: "Empty: derived from the base DN.", Kind: Text},
	{Key: "ldap_ssh_key_attribute", Section: "Directory (LDAP)", Label: "SSH key attribute", Help: "Empty: ipaSshPubKey (FreeIPA) or sshPublicKey (openssh-lpk).", Kind: Text},
	{Key: "ldap_id_min", Section: "Directory (LDAP)", Label: "First uid/gid number (OpenLDAP)", Help: "FreeIPA allocates its own.", Kind: Int, Default: "10000", Min: 1000},
	{Key: "ldap_home_prefix", Section: "Directory (LDAP)", Label: "Home directory prefix", Kind: Text, Default: "/home"},
	{Key: "ldap_login_shell", Section: "Directory (LDAP)", Label: "Login shell", Kind: Text, Default: "/bin/bash"},
	{Key: "ldap_timeout_seconds", Section: "Directory (LDAP)", Label: "Timeout (seconds)", Kind: Int, Default: "10", Min: 1},

	{Key: "notify_provider", Section: "Notifications", Label: "Delivery", Kind: Select, Options: []string{"mailjet", "smtp", "log", "none"}, Default: "mailjet"},
	{Key: "mail_from_address", Section: "Notifications", Label: "From address", Kind: Text},
	{Key: "mail_from_name", Section: "Notifications", Label: "From name", Help: "Empty uses the site name.", Kind: Text},
	{Key: "mailjet_api_key", Section: "Notifications", Label: "Mailjet API key", Kind: Secret},
	{Key: "mailjet_api_secret", Section: "Notifications", Label: "Mailjet API secret", Kind: Secret},
	{Key: "mailjet_api_url", Section: "Notifications", Label: "Mailjet send URL", Kind: Text, Default: "https://api.mailjet.com/v3.1/send"},
	{Key: "smtp_host", Section: "Notifications", Label: "SMTP host", Kind: Text},
	{Key: "smtp_port", Section: "Notifications", Label: "SMTP port", Kind: Int, Default: "587", Min: 1},
	{Key: "smtp_security", Section: "Notifications", Label: "SMTP security", Kind: Select, Options: []string{"starttls", "tls", "none"}, Default: "starttls"},
	{Key: "smtp_username", Section: "Notifications", Label: "SMTP username", Kind: Text},
	{Key: "smtp_password", Section: "Notifications", Label: "SMTP password", Kind: Secret},

	{Key: "editable_fields", Section: "Profile", Label: "Fields users may edit", Help: "Any of: given_name, surname, display_name, email, phone, mobile, title.", Kind: List, Default: "given_name,surname,display_name,email,phone,mobile,title"},
	{Key: "ssh_key_types", Section: "Profile", Label: "Allowed SSH key types", Kind: List, Default: "ssh-ed25519,ssh-rsa,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,sk-ssh-ed25519@openssh.com,sk-ecdsa-sha2-nistp256@openssh.com"},
	{Key: "ssh_rsa_min_bits", Section: "Profile", Label: "Minimum RSA key size", Kind: Int, Default: "3072", Min: 1024},
	{Key: "ssh_max_keys", Section: "Profile", Label: "Maximum keys per user", Kind: Int, Default: "10", Min: 1},
	{Key: "gravatar_enabled", Section: "Profile", Label: "Show Gravatar images", Kind: Bool, Default: "true"},
	{Key: "gravatar_default", Section: "Profile", Label: "Gravatar fallback image", Kind: Select, Options: []string{"identicon", "mp", "retro", "robohash", "monsterid", "wavatar", "blank"}, Default: "identicon"},
}

var defIndex = func() map[string]Def {
	m := map[string]Def{}
	for _, d := range Defs {
		m[d.Key] = d
	}
	return m
}()

// Lookup returns the definition for key.
func Lookup(key string) (Def, bool) { d, ok := defIndex[key]; return d, ok }

// Env reads an environment value, honouring NAME_FILE (container secrets). See DETAILS.md §Secrets.
func Env(name string) (string, bool, error) {
	if path := os.Getenv(name + "_FILE"); path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			return "", false, fmt.Errorf("%s_FILE: %w", name, err)
		}
		return strings.TrimRight(string(b), "\r\n"), true, nil
	}
	v, ok := os.LookupEnv(name)
	return v, ok, nil
}

// Settings holds the current effective values.
type Settings struct {
	store  *store.Store
	sealer *secret.Sealer

	mu      sync.RWMutex
	env     map[string]string // locked values from SAM_* env
	db      map[string]string // stored values (secrets still sealed)
	version uint64
}

// Load reads env and the database.
func Load(ctx context.Context, st *store.Store, sealer *secret.Sealer) (*Settings, error) {
	s := &Settings{store: st, sealer: sealer, env: map[string]string{}}
	for _, d := range Defs {
		v, ok, err := Env(d.EnvName())
		if err != nil {
			return nil, err
		}
		if ok {
			if err := Validate(d, v); err != nil {
				return nil, fmt.Errorf("%s: %w", d.EnvName(), err)
			}
			s.env[d.Key] = v
		}
	}
	return s, s.Reload(ctx)
}

// Reload re-reads stored values.
func (s *Settings) Reload(ctx context.Context) error {
	db, err := s.store.AllSettings(ctx)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.db = db
	s.version++
	s.mu.Unlock()
	return nil
}

// Version changes whenever settings change (to rebuild cached clients).
func (s *Settings) Version() uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.version
}

// Locked reports whether key is set by environment (read-only in the UI).
func (s *Settings) Locked(key string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.env[key]
	return ok
}

// IsSet reports whether key has a non-default value from env or the database.
func (s *Settings) IsSet(key string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if v, ok := s.env[key]; ok {
		return v != ""
	}
	v, ok := s.db[key]
	return ok && v != ""
}

// Get returns the effective value (secrets decrypted).
func (s *Settings) Get(key string) string {
	d, ok := defIndex[key]
	if !ok {
		panic("unknown setting " + key)
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if v, ok := s.env[key]; ok {
		return v
	}
	if v, ok := s.db[key]; ok {
		if d.Kind == Secret {
			if v == "" {
				return ""
			}
			pt, err := s.sealer.OpenString(v, "setting:"+key)
			if err != nil {
				return ""
			}
			return pt
		}
		return v
	}
	return d.Default
}

// Bool returns a boolean setting.
func (s *Settings) Bool(key string) bool { b, _ := strconv.ParseBool(s.Get(key)); return b }

// Int returns an integer setting.
func (s *Settings) Int(key string) int {
	n, err := strconv.Atoi(s.Get(key))
	if err != nil {
		n, _ = strconv.Atoi(defIndex[key].Default)
	}
	return n
}

// List returns a comma separated setting as trimmed, non-empty items.
func (s *Settings) List(key string) []string { return SplitList(s.Get(key)) }

// SplitList splits on commas and newlines.
func SplitList(v string) []string {
	var out []string
	for _, p := range strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == '\n' }) {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// Set validates and stores a value; secrets are sealed. An empty value resets to default (except secrets: see Clear).
func (s *Settings) Set(ctx context.Context, key, value, by string) error {
	d, ok := defIndex[key]
	if !ok {
		return fmt.Errorf("unknown setting %q", key)
	}
	if s.Locked(key) {
		return fmt.Errorf("%s is set by %s and cannot be changed here", d.Label, d.EnvName())
	}
	if d.Kind == List {
		value = strings.Join(SplitList(value), ",")
	}
	if err := Validate(d, value); err != nil {
		return fmt.Errorf("%s: %w", d.Label, err)
	}
	if value == "" || (d.Kind != Secret && value == d.Default) {
		if err := s.store.DeleteSetting(ctx, key); err != nil {
			return err
		}
	} else {
		stored := value
		if d.Kind == Secret {
			stored = s.sealer.SealString(value, "setting:"+key)
		}
		if err := s.store.PutSetting(ctx, key, stored, by); err != nil {
			return err
		}
	}
	return s.Reload(ctx)
}

// Validate checks a value against its definition.
func Validate(d Def, v string) error {
	switch d.Kind {
	case Bool:
		if _, err := strconv.ParseBool(v); err != nil && v != "" {
			return errors.New("must be true or false")
		}
	case Int:
		if v == "" {
			return nil
		}
		n, err := strconv.Atoi(v)
		if err != nil {
			return errors.New("must be a whole number")
		}
		if n < d.Min {
			return fmt.Errorf("must be at least %d", d.Min)
		}
	case Select:
		if v == "" {
			return nil
		}
		for _, o := range d.Options {
			if v == o {
				return nil
			}
		}
		return fmt.Errorf("must be one of %s", strings.Join(d.Options, ", "))
	}
	switch d.Key {
	case "username_pattern", "group_name_pattern":
		if v != "" {
			if _, err := regexp.Compile(v); err != nil {
				return fmt.Errorf("invalid regular expression: %v", err)
			}
		}
	case "ldap_url":
		if v != "" {
			u, err := url.Parse(v)
			if err != nil || (u.Scheme != "ldap" && u.Scheme != "ldaps") || u.Host == "" {
				return errors.New("must look like ldaps://host or ldap://host")
			}
		}
	case "oidc_issuer", "mailjet_api_url":
		if v != "" {
			u, err := url.Parse(v)
			if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
				return errors.New("must be an http(s) URL")
			}
		}
	case "ldap_ca_cert":
		if strings.TrimSpace(v) != "" {
			if err := checkPEM(v); err != nil {
				return err
			}
		}
	case "editable_fields":
		for _, f := range SplitList(v) {
			if !validField[f] {
				return fmt.Errorf("unknown field %q", f)
			}
		}
	}
	return nil
}

var validField = map[string]bool{"given_name": true, "surname": true, "display_name": true, "email": true, "phone": true, "mobile": true, "title": true}

func checkPEM(v string) error {
	rest := []byte(v)
	n := 0
	for {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		if b.Type != "CERTIFICATE" {
			continue
		}
		if _, err := x509.ParseCertificate(b.Bytes); err != nil {
			return fmt.Errorf("certificate %d: %v", n+1, err)
		}
		n++
	}
	if n == 0 {
		return errors.New("no PEM certificate found")
	}
	return nil
}
