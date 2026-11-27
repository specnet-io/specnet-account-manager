package directory

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/specnet-io/specnet-account-manager/internal/secret"
)

// Config is the LDAP connection and schema profile. See DETAILS.md §Directory.
type Config struct {
	Profile            string // "freeipa" or "openldap"
	URL                string
	StartTLS           bool
	CACert             string
	InsecureSkipVerify bool
	BindDN             string
	BindPassword       string
	BaseDN             string
	UserBase           string
	GroupBase          string
	Realm              string
	SSHAttr            string
	IDMin              int
	HomePrefix         string
	Shell              string
	Timeout            time.Duration
	// FASGroups (FreeIPA): group search finds only FAS groups (objectClass fasGroup), and new groups are created as FAS
	// groups. SAM's web layer refuses to manage the others. See DETAILS.md §Directory.
	FASGroups bool
}

// LDAP implements Directory over LDAP/LDAPS.
type LDAP struct {
	cfg Config
	mu  sync.Mutex // serialises uid/gid allocation (OpenLDAP profile)
}

// NewLDAP fills profile defaults and returns a client. Connections are opened per operation (low load).
func NewLDAP(cfg Config) (*LDAP, error) {
	if cfg.URL == "" || cfg.BaseDN == "" {
		return nil, ErrNotConfigured
	}
	if cfg.Profile == "" {
		cfg.Profile = "freeipa"
	}
	ipa := cfg.Profile == "freeipa"
	if cfg.UserBase == "" {
		if ipa {
			cfg.UserBase = "cn=users,cn=accounts," + cfg.BaseDN
		} else {
			cfg.UserBase = "ou=people," + cfg.BaseDN
		}
	}
	if cfg.GroupBase == "" {
		if ipa {
			cfg.GroupBase = "cn=groups,cn=accounts," + cfg.BaseDN
		} else {
			cfg.GroupBase = "ou=groups," + cfg.BaseDN
		}
	}
	if cfg.SSHAttr == "" {
		if ipa {
			cfg.SSHAttr = "ipaSshPubKey"
		} else {
			cfg.SSHAttr = "sshPublicKey"
		}
	}
	if cfg.Realm == "" && ipa {
		cfg.Realm = realmFromBase(cfg.BaseDN)
	}
	if cfg.IDMin == 0 {
		cfg.IDMin = 10000
	}
	if cfg.HomePrefix == "" {
		cfg.HomePrefix = "/home"
	}
	if cfg.Shell == "" {
		cfg.Shell = "/bin/bash"
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 10 * time.Second
	}
	return &LDAP{cfg: cfg}, nil
}

func realmFromBase(base string) string {
	dn, err := ldap.ParseDN(base)
	if err != nil {
		return ""
	}
	var parts []string
	for _, rdn := range dn.RDNs {
		for _, a := range rdn.Attributes {
			if strings.EqualFold(a.Type, "dc") {
				parts = append(parts, a.Value)
			}
		}
	}
	return strings.ToUpper(strings.Join(parts, "."))
}

func (l *LDAP) ipa() bool { return l.cfg.Profile == "freeipa" }

// fas reports whether only FreeIPA FAS groups are in scope.
func (l *LDAP) fas() bool { return l.ipa() && l.cfg.FASGroups }

// groupAttrs are read for every group.
var groupAttrs = []string{"cn", "description", "member", "objectClass"}

func (l *LDAP) tlsConfig() (*tls.Config, error) {
	u, err := url.Parse(l.cfg.URL)
	if err != nil {
		return nil, err
	}
	tc := &tls.Config{ServerName: u.Hostname(), MinVersion: tls.VersionTLS12, InsecureSkipVerify: l.cfg.InsecureSkipVerify} //nolint:gosec // opt-in, testing only
	if strings.TrimSpace(l.cfg.CACert) != "" {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM([]byte(l.cfg.CACert)) {
			return nil, errors.New("LDAP CA certificate is not valid PEM")
		}
		tc.RootCAs = pool
	}
	return tc, nil
}

// dial opens a connection, applies TLS, and binds as bindDN (service account when empty).
func (l *LDAP) dial(ctx context.Context, bindDN, password string) (*ldap.Conn, error) {
	tc, err := l.tlsConfig()
	if err != nil {
		return nil, err
	}
	d := &net.Dialer{Timeout: l.cfg.Timeout}
	if dl, ok := ctx.Deadline(); ok {
		d.Deadline = dl
	}
	conn, err := ldap.DialURL(l.cfg.URL, ldap.DialWithDialer(d), ldap.DialWithTLSConfig(tc))
	if err != nil {
		return nil, fmt.Errorf("connect to directory: %w", err)
	}
	conn.SetTimeout(l.cfg.Timeout)
	if strings.HasPrefix(strings.ToLower(l.cfg.URL), "ldap://") && l.cfg.StartTLS {
		if err := conn.StartTLS(tc); err != nil {
			conn.Close()
			return nil, fmt.Errorf("directory StartTLS: %w", err)
		}
	}
	if bindDN == "" {
		bindDN, password = l.cfg.BindDN, l.cfg.BindPassword
	}
	if bindDN != "" {
		if password == "" {
			conn.Close()
			return nil, ErrInvalidCreds // never allow an unauthenticated simple bind
		}
		if err := conn.Bind(bindDN, password); err != nil {
			conn.Close()
			if ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
				return nil, ErrInvalidCreds
			}
			return nil, fmt.Errorf("directory bind: %w", err)
		}
	}
	return conn, nil
}

func (l *LDAP) service(ctx context.Context) (*ldap.Conn, error) {
	conn, err := l.dial(ctx, "", "")
	if errors.Is(err, ErrInvalidCreds) {
		return nil, errors.New("the directory rejected the service account credentials")
	}
	return conn, err
}

// Ping binds with the service account and reads the user base.
func (l *LDAP) Ping(ctx context.Context) error {
	conn, err := l.service(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	for _, base := range []string{l.cfg.UserBase, l.cfg.GroupBase} {
		_, err := conn.Search(ldap.NewSearchRequest(base, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 0, false, "(objectClass=*)", []string{"1.1"}, nil))
		if err != nil {
			return fmt.Errorf("read %s: %w", base, err)
		}
	}
	return nil
}

func (l *LDAP) userAttrs() []string {
	return []string{"uid", "givenName", "sn", "displayName", "cn", "mail", "telephoneNumber", "mobile", "title", "nsAccountLock", l.cfg.SSHAttr}
}

func (l *LDAP) toUser(e *ldap.Entry) *User {
	u := &User{DN: e.DN, Username: e.GetAttributeValue("uid")}
	u.GivenName = e.GetAttributeValue("givenName")
	u.Surname = e.GetAttributeValue("sn")
	u.DisplayName = e.GetAttributeValue("displayName")
	if u.DisplayName == "" {
		u.DisplayName = e.GetAttributeValue("cn")
	}
	u.Email = e.GetAttributeValue("mail")
	u.Phone = e.GetAttributeValue("telephoneNumber")
	u.Mobile = e.GetAttributeValue("mobile")
	u.Title = e.GetAttributeValue("title")
	u.SSHKeys = e.GetAttributeValues(l.cfg.SSHAttr)
	u.Disabled = strings.EqualFold(e.GetAttributeValue("nsAccountLock"), "true")
	return u
}

func (l *LDAP) findUser(conn *ldap.Conn, filter string) (*User, error) {
	res, err := conn.Search(ldap.NewSearchRequest(l.cfg.UserBase, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 2, 0, false,
		"(&(objectClass=posixAccount)"+filter+")", l.userAttrs(), nil))
	if err != nil {
		if ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	switch len(res.Entries) {
	case 0:
		return nil, ErrNotFound
	case 1:
		return l.toUser(res.Entries[0]), nil
	default:
		return nil, errors.New("more than one directory account matches")
	}
}

// GetUser looks a user up by uid.
func (l *LDAP) GetUser(ctx context.Context, username string) (*User, error) {
	if username == "" {
		return nil, ErrNotFound
	}
	conn, err := l.service(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	return l.findUser(conn, "(uid="+ldap.EscapeFilter(username)+")")
}

// FindUserByEmail looks a user up by mail.
func (l *LDAP) FindUserByEmail(ctx context.Context, email string) (*User, error) {
	if email == "" {
		return nil, ErrNotFound
	}
	conn, err := l.service(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	return l.findUser(conn, "(mail="+ldap.EscapeFilter(email)+")")
}

// SearchUsers finds users by uid/cn/mail substring.
func (l *LDAP) SearchUsers(ctx context.Context, query string, limit int) ([]*User, error) {
	conn, err := l.service(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	filter := "(objectClass=posixAccount)"
	if q := strings.TrimSpace(query); q != "" {
		e := ldap.EscapeFilter(q)
		filter = "(&(objectClass=posixAccount)(|(uid=*" + e + "*)(cn=*" + e + "*)(mail=*" + e + "*)))"
	}
	res, err := conn.Search(ldap.NewSearchRequest(l.cfg.UserBase, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, limit, 0, false, filter, l.userAttrs(), nil))
	if err != nil && !ldap.IsErrorWithCode(err, ldap.LDAPResultSizeLimitExceeded) {
		return nil, err
	}
	var out []*User
	if res != nil {
		for _, e := range res.Entries {
			out = append(out, l.toUser(e))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Username < out[j].Username })
	return out, nil
}

func (l *LDAP) userDN(username string) string {
	return "uid=" + escapeDN(username) + "," + l.cfg.UserBase
}

func (l *LDAP) groupDN(name string) string {
	return "cn=" + escapeDN(name) + "," + l.cfg.GroupBase
}

// CreateUser adds an account with no usable password; the user sets one from the emailed link.
func (l *LDAP) CreateUser(ctx context.Context, nu NewUser) error {
	conn, err := l.service(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	if _, err := l.findUser(conn, "(uid="+ldap.EscapeFilter(nu.Username)+")"); err == nil {
		return ErrExists
	} else if !errors.Is(err, ErrNotFound) {
		return err
	}
	cn := strings.TrimSpace(nu.GivenName + " " + nu.Surname)
	req := ldap.NewAddRequest(l.userDN(nu.Username), nil)
	req.Attribute("uid", []string{nu.Username})
	req.Attribute("givenName", []string{nu.GivenName})
	req.Attribute("sn", []string{nu.Surname})
	req.Attribute("cn", []string{cn})
	req.Attribute("displayName", []string{cn})
	req.Attribute("mail", []string{nu.Email})
	req.Attribute("homeDirectory", []string{strings.TrimRight(l.cfg.HomePrefix, "/") + "/" + nu.Username})
	req.Attribute("loginShell", []string{l.cfg.Shell})
	if l.ipa() {
		// See DETAILS.md §FreeIPA: -1 / autogenerate trigger IPA's DNA, UUID and managed-entry plugins.
		principal := nu.Username + "@" + l.cfg.Realm
		req.Attribute("objectClass", []string{"top", "person", "organizationalperson", "inetorgperson", "inetuser", "posixaccount",
			"krbprincipalaux", "krbticketpolicyaux", "ipaobject", "ipasshuser", "ipaSshGroupOfPubKeys", "mepOriginEntry"})
		req.Attribute("gecos", []string{cn})
		req.Attribute("initials", []string{initials(nu.GivenName, nu.Surname)})
		req.Attribute("uidNumber", []string{"-1"})
		req.Attribute("gidNumber", []string{"-1"})
		req.Attribute("krbPrincipalName", []string{principal})
		req.Attribute("krbCanonicalName", []string{principal})
		req.Attribute("ipaUniqueID", []string{"autogenerate"})
		if err := conn.Add(req); err != nil {
			return mapWriteErr(err)
		}
		// IPA's own user-add also puts new users in ipausers; failing that is not fatal.
		_ = l.addMember(conn, "ipausers", l.userDN(nu.Username))
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	id, err := l.nextID(conn)
	if err != nil {
		return err
	}
	req.Attribute("objectClass", []string{"top", "inetOrgPerson", "posixAccount"})
	req.Attribute("uidNumber", []string{strconv.Itoa(id)})
	req.Attribute("gidNumber", []string{strconv.Itoa(id)})
	if err := conn.Add(req); err != nil {
		return mapWriteErr(err)
	}
	return nil
}

func initials(g, s string) string {
	var b strings.Builder
	for _, p := range []string{g, s} {
		if r := []rune(strings.TrimSpace(p)); len(r) > 0 {
			b.WriteRune(r[0])
		}
	}
	return strings.ToUpper(b.String())
}

// nextID returns max(uidNumber)+1 at or above IDMin (OpenLDAP profile).
func (l *LDAP) nextID(conn *ldap.Conn) (int, error) {
	res, err := conn.SearchWithPaging(ldap.NewSearchRequest(l.cfg.BaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(|(uidNumber>="+strconv.Itoa(l.cfg.IDMin)+")(gidNumber>="+strconv.Itoa(l.cfg.IDMin)+"))", []string{"uidNumber", "gidNumber"}, nil), 500)
	if err != nil {
		return 0, fmt.Errorf("allocate uid: %w", err)
	}
	maxID := l.cfg.IDMin - 1
	for _, e := range res.Entries {
		for _, a := range []string{"uidNumber", "gidNumber"} {
			if n, err := strconv.Atoi(e.GetAttributeValue(a)); err == nil && n > maxID {
				maxID = n
			}
		}
	}
	return maxID + 1, nil
}

// SetPassword sets a password without knowing the old one (reset/setup links).
// On FreeIPA an administrative set leaves the password expired, so it is followed by a
// self-change from a throwaway password. See DETAILS.md §Passwords.
func (l *LDAP) SetPassword(ctx context.Context, username, password string) error {
	conn, err := l.service(ctx)
	if err != nil {
		return err
	}
	u, err := l.findUser(conn, "(uid="+ldap.EscapeFilter(username)+")")
	if err != nil {
		conn.Close()
		return err
	}
	if !l.ipa() {
		defer conn.Close()
		if _, err := conn.PasswordModify(ldap.NewPasswordModifyRequest(u.DN, "", password)); err != nil {
			return mapPasswordErr(err)
		}
		return nil
	}
	temp := secret.Password()
	_, err = conn.PasswordModify(ldap.NewPasswordModifyRequest(u.DN, "", temp))
	conn.Close()
	if err != nil {
		return mapPasswordErr(err)
	}
	return l.ChangePassword(ctx, username, temp, password)
}

// ExpirePassword sets a random password so the old one stops working (forced reset).
func (l *LDAP) ExpirePassword(ctx context.Context, username string) error {
	conn, err := l.service(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	u, err := l.findUser(conn, "(uid="+ldap.EscapeFilter(username)+")")
	if err != nil {
		return err
	}
	if _, err := conn.PasswordModify(ldap.NewPasswordModifyRequest(u.DN, "", secret.Password())); err != nil {
		return mapPasswordErr(err)
	}
	return nil
}

// ChangePassword binds as the user and changes their own password.
func (l *LDAP) ChangePassword(ctx context.Context, username, oldPassword, newPassword string) error {
	if oldPassword == "" {
		return ErrInvalidCreds
	}
	dn, err := l.dnOf(ctx, username)
	if err != nil {
		return err
	}
	conn, err := l.dial(ctx, dn, oldPassword)
	if err != nil {
		return err
	}
	defer conn.Close()
	if _, err := conn.PasswordModify(ldap.NewPasswordModifyRequest(dn, oldPassword, newPassword)); err != nil {
		return mapPasswordErr(err)
	}
	return nil
}

func (l *LDAP) dnOf(ctx context.Context, username string) (string, error) {
	u, err := l.GetUser(ctx, username)
	if err != nil {
		return "", err
	}
	return u.DN, nil
}

// UpdateContact replaces the contact attributes (empty values remove the attribute).
func (l *LDAP) UpdateContact(ctx context.Context, username string, c Contact) error {
	conn, err := l.service(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	u, err := l.findUser(conn, "(uid="+ldap.EscapeFilter(username)+")")
	if err != nil {
		return err
	}
	if strings.TrimSpace(c.Surname) == "" {
		return errors.New("last name is required")
	}
	req := ldap.NewModifyRequest(u.DN, nil)
	set := func(attr, oldV, newV string) {
		if oldV == newV {
			return
		}
		if newV == "" {
			req.Replace(attr, []string{})
		} else {
			req.Replace(attr, []string{newV})
		}
	}
	set("givenName", u.GivenName, c.GivenName)
	set("sn", u.Surname, c.Surname)
	set("displayName", u.DisplayName, c.DisplayName)
	set("mail", u.Email, c.Email)
	set("telephoneNumber", u.Phone, c.Phone)
	set("mobile", u.Mobile, c.Mobile)
	set("title", u.Title, c.Title)
	if c.GivenName != u.GivenName || c.Surname != u.Surname {
		cn := strings.TrimSpace(c.GivenName + " " + c.Surname)
		req.Replace("cn", []string{cn})
		if l.ipa() {
			req.Replace("gecos", []string{cn})
			req.Replace("initials", []string{initials(c.GivenName, c.Surname)})
		}
	}
	if len(req.Changes) == 0 {
		return nil
	}
	return mapWriteErr(conn.Modify(req))
}

// SetSSHKeys replaces the user's SSH public keys.
func (l *LDAP) SetSSHKeys(ctx context.Context, username string, keys []string) error {
	conn, err := l.service(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	res, err := conn.Search(ldap.NewSearchRequest(l.cfg.UserBase, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 2, 0, false,
		"(&(objectClass=posixAccount)(uid="+ldap.EscapeFilter(username)+"))", []string{"objectClass"}, nil))
	if err != nil {
		return err
	}
	if len(res.Entries) != 1 {
		return ErrNotFound
	}
	e := res.Entries[0]
	need := "ldapPublicKey"
	if l.ipa() {
		need = "ipasshuser"
	}
	req := ldap.NewModifyRequest(e.DN, nil)
	if !hasValueFold(e.GetAttributeValues("objectClass"), need) {
		req.Add("objectClass", []string{need})
	}
	if keys == nil {
		keys = []string{}
	}
	req.Replace(l.cfg.SSHAttr, keys)
	return mapWriteErr(conn.Modify(req))
}

func hasValueFold(vals []string, v string) bool {
	for _, x := range vals {
		if strings.EqualFold(x, v) {
			return true
		}
	}
	return false
}

// ---- CA certificates ----

// CACertificates reads FreeIPA's CA store, cn=certificates,cn=ipa,cn=etc,<base>: one entry per CA the domain trusts
// (the IPA CA, an external root and any intermediates), each with cACertificate;binary. Distrusted ones are skipped.
func (l *LDAP) CACertificates(ctx context.Context) ([][]byte, error) {
	if !l.ipa() {
		return nil, nil
	}
	conn, err := l.service(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	res, err := conn.Search(ldap.NewSearchRequest("cn=certificates,cn=ipa,cn=etc,"+l.cfg.BaseDN, ldap.ScopeSingleLevel, ldap.NeverDerefAliases, 100, 0, false,
		"(objectClass=ipaCertificate)", []string{"cACertificate;binary", "ipaKeyTrust"}, nil))
	if err != nil {
		if ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject) {
			return nil, nil
		}
		return nil, err
	}
	var out [][]byte
	for _, e := range res.Entries {
		if strings.EqualFold(e.GetAttributeValue("ipaKeyTrust"), "distrusted") {
			continue
		}
		for _, a := range e.Attributes {
			if strings.HasPrefix(strings.ToLower(a.Name), "cacertificate") {
				out = append(out, a.ByteValues...)
			}
		}
	}
	return out, nil
}

// ---- groups ----

func (l *LDAP) toGroup(e *ldap.Entry) *Group {
	g := &Group{DN: e.DN, Name: e.GetAttributeValue("cn"), Description: e.GetAttributeValue("description"),
		FAS: hasValueFold(e.GetAttributeValues("objectClass"), "fasGroup")}
	for _, m := range e.GetAttributeValues("member") {
		if u := uidFromDN(m); u != "" {
			g.Members = append(g.Members, u)
		}
	}
	sort.Strings(g.Members)
	return g
}

func uidFromDN(dn string) string {
	p, err := ldap.ParseDN(dn)
	if err != nil || len(p.RDNs) == 0 {
		return ""
	}
	for _, a := range p.RDNs[0].Attributes {
		if strings.EqualFold(a.Type, "uid") {
			return a.Value
		}
	}
	return ""
}

func (l *LDAP) findGroup(conn *ldap.Conn, name string) (*Group, error) {
	res, err := conn.Search(ldap.NewSearchRequest(l.cfg.GroupBase, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 2, 0, false,
		"(&(objectClass=groupOfNames)(cn="+ldap.EscapeFilter(name)+"))", groupAttrs, nil))
	if err != nil {
		if ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	if len(res.Entries) != 1 {
		return nil, ErrNotFound
	}
	return l.toGroup(res.Entries[0]), nil
}

// GetGroup looks a group up by cn.
func (l *LDAP) GetGroup(ctx context.Context, name string) (*Group, error) {
	conn, err := l.service(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	return l.findGroup(conn, name)
}

// SearchGroups finds groups by cn substring.
func (l *LDAP) SearchGroups(ctx context.Context, query string, limit int) ([]*Group, error) {
	conn, err := l.service(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	filter := "(objectClass=groupOfNames)"
	if l.fas() {
		filter += "(objectClass=fasGroup)"
	}
	if q := strings.TrimSpace(query); q != "" {
		filter += "(cn=*" + ldap.EscapeFilter(q) + "*)"
	}
	res, err := conn.Search(ldap.NewSearchRequest(l.cfg.GroupBase, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, limit, 0, false, "(&"+filter+")", []string{"cn", "description", "objectClass"}, nil))
	if err != nil && !ldap.IsErrorWithCode(err, ldap.LDAPResultSizeLimitExceeded) {
		return nil, err
	}
	var out []*Group
	if res != nil {
		for _, e := range res.Entries {
			out = append(out, l.toGroup(e))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// CreateGroup adds a group with one initial member (groupOfNames needs at least one on OpenLDAP).
func (l *LDAP) CreateGroup(ctx context.Context, name, description, firstMember string) error {
	conn, err := l.service(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	if _, err := l.findGroup(conn, name); err == nil {
		return ErrExists
	}
	owner, err := l.findUser(conn, "(uid="+ldap.EscapeFilter(firstMember)+")")
	if err != nil {
		return fmt.Errorf("first member %s: %w", firstMember, err)
	}
	req := ldap.NewAddRequest(l.groupDN(name), nil)
	req.Attribute("cn", []string{name})
	if description != "" {
		req.Attribute("description", []string{description})
	}
	req.Attribute("member", []string{owner.DN})
	if l.ipa() {
		oc := []string{"top", "groupofnames", "nestedgroup", "ipausergroup", "ipaobject", "posixgroup"}
		if l.fas() {
			oc = append(oc, "fasgroup")
		}
		req.Attribute("objectClass", oc)
		req.Attribute("gidNumber", []string{"-1"})
		req.Attribute("ipaUniqueID", []string{"autogenerate"})
	} else {
		req.Attribute("objectClass", []string{"top", "groupOfNames"})
	}
	return mapWriteErr(conn.Add(req))
}

// DeleteGroup removes a group.
func (l *LDAP) DeleteGroup(ctx context.Context, name string) error {
	conn, err := l.service(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	g, err := l.findGroup(conn, name)
	if err != nil {
		return err
	}
	return mapWriteErr(conn.Del(ldap.NewDelRequest(g.DN, nil)))
}

// SetGroupDescription replaces a group's description.
func (l *LDAP) SetGroupDescription(ctx context.Context, name, description string) error {
	conn, err := l.service(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	g, err := l.findGroup(conn, name)
	if err != nil {
		return err
	}
	req := ldap.NewModifyRequest(g.DN, nil)
	if description == "" {
		req.Replace("description", []string{})
	} else {
		req.Replace("description", []string{description})
	}
	return mapWriteErr(conn.Modify(req))
}

func (l *LDAP) addMember(conn *ldap.Conn, group, memberDN string) error {
	g, err := l.findGroup(conn, group)
	if err != nil {
		return err
	}
	req := ldap.NewModifyRequest(g.DN, nil)
	req.Add("member", []string{memberDN})
	err = conn.Modify(req)
	if ldap.IsErrorWithCode(err, ldap.LDAPResultAttributeOrValueExists) {
		return nil
	}
	return mapWriteErr(err)
}

// AddMember adds a user to a group (idempotent).
func (l *LDAP) AddMember(ctx context.Context, group, username string) error {
	conn, err := l.service(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	u, err := l.findUser(conn, "(uid="+ldap.EscapeFilter(username)+")")
	if err != nil {
		return err
	}
	return l.addMember(conn, group, u.DN)
}

// RemoveMember removes a user from a group (idempotent).
func (l *LDAP) RemoveMember(ctx context.Context, group, username string) error {
	conn, err := l.service(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	u, err := l.findUser(conn, "(uid="+ldap.EscapeFilter(username)+")")
	if err != nil {
		return err
	}
	g, err := l.findGroup(conn, group)
	if err != nil {
		return err
	}
	req := ldap.NewModifyRequest(g.DN, nil)
	req.Delete("member", []string{u.DN})
	err = conn.Modify(req)
	switch {
	case err == nil, ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchAttribute):
		return nil
	case ldap.IsErrorWithCode(err, ldap.LDAPResultObjectClassViolation):
		return errors.New("a group must keep at least one member in this directory")
	}
	return mapWriteErr(err)
}

// UserGroups lists the groups the user is a direct member of.
func (l *LDAP) UserGroups(ctx context.Context, username string) ([]string, error) {
	conn, err := l.service(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	u, err := l.findUser(conn, "(uid="+ldap.EscapeFilter(username)+")")
	if err != nil {
		return nil, err
	}
	res, err := conn.SearchWithPaging(ldap.NewSearchRequest(l.cfg.GroupBase, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(&(objectClass=groupOfNames)(member="+ldap.EscapeFilter(u.DN)+"))", []string{"cn"}, nil), 500)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range res.Entries {
		out = append(out, e.GetAttributeValue("cn"))
	}
	sort.Strings(out)
	return out, nil
}

func mapWriteErr(err error) error {
	switch {
	case err == nil:
		return nil
	case ldap.IsErrorWithCode(err, ldap.LDAPResultEntryAlreadyExists):
		return ErrExists
	case ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject):
		return ErrNotFound
	case ldap.IsErrorWithCode(err, ldap.LDAPResultInsufficientAccessRights):
		return errors.New("the service account is not allowed to make this change in the directory")
	}
	return fmt.Errorf("directory: %w", err)
}

func mapPasswordErr(err error) error {
	var le *ldap.Error
	switch {
	case ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials):
		return ErrInvalidCreds
	case ldap.IsErrorWithCode(err, ldap.LDAPResultConstraintViolation), ldap.IsErrorWithCode(err, ldap.LDAPResultUnwillingToPerform):
		if errors.As(err, &le) && le.Err != nil {
			if msg := strings.TrimSpace(le.Err.Error()); msg != "" {
				return fmt.Errorf("%w: %s", ErrPasswordPolicy, msg)
			}
		}
		return ErrPasswordPolicy
	}
	return mapWriteErr(err)
}

// escapeDN escapes an RDN value (RFC 4514).
func escapeDN(v string) string {
	var b strings.Builder
	for i, r := range v {
		switch {
		case r == ',' || r == '+' || r == '"' || r == '\\' || r == '<' || r == '>' || r == ';' || r == '=':
			b.WriteByte('\\')
			b.WriteRune(r)
		case (r == ' ' || r == '#') && i == 0, r == ' ' && i == len(v)-1:
			b.WriteByte('\\')
			b.WriteRune(r)
		case r == 0:
			b.WriteString("\\00")
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}
