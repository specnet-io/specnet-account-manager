// Package directory is the LDAP source of truth for users and groups. See DETAILS.md §Directory.
package directory

import (
	"context"
	"errors"
	"strings"
)

// Errors callers can branch on.
var (
	ErrNotFound       = errors.New("not found in the directory")
	ErrExists         = errors.New("already exists in the directory")
	ErrInvalidCreds   = errors.New("the current password is not correct")
	ErrPasswordPolicy = errors.New("the directory rejected the password (too short, too simple or reused?)")
	ErrNotConfigured  = errors.New("the directory connection is not configured yet")
)

// Contact holds the user-editable fields.
type Contact struct {
	GivenName   string
	Surname     string
	DisplayName string
	Email       string
	Phone       string
	Mobile      string
	Title       string
}

// Get returns a field by its settings name (see settings "editable_fields").
func (c *Contact) Get(field string) string {
	switch field {
	case "given_name":
		return c.GivenName
	case "surname":
		return c.Surname
	case "display_name":
		return c.DisplayName
	case "email":
		return c.Email
	case "phone":
		return c.Phone
	case "mobile":
		return c.Mobile
	case "title":
		return c.Title
	}
	return ""
}

// Set sets a field by its settings name.
func (c *Contact) Set(field, v string) {
	switch field {
	case "given_name":
		c.GivenName = v
	case "surname":
		c.Surname = v
	case "display_name":
		c.DisplayName = v
	case "email":
		c.Email = v
	case "phone":
		c.Phone = v
	case "mobile":
		c.Mobile = v
	case "title":
		c.Title = v
	}
}

// ContactFields lists the fields in display order with labels.
var ContactFields = []struct{ Key, Label string }{
	{"given_name", "First name"},
	{"surname", "Last name"},
	{"display_name", "Display name"},
	{"email", "Email"},
	{"phone", "Phone"},
	{"mobile", "Mobile"},
	{"title", "Job title"},
}

// User is a directory account.
type User struct {
	DN       string
	Username string
	Contact
	SSHKeys  []string
	Disabled bool
}

// Name is the best human name for the user.
func (u *User) Name() string {
	if u.DisplayName != "" {
		return u.DisplayName
	}
	if n := strings.TrimSpace(u.GivenName + " " + u.Surname); n != "" {
		return n
	}
	return u.Username
}

// Group is a directory group; Members are usernames of direct user members.
type Group struct {
	DN          string
	Name        string
	Description string
	Members     []string
	FAS         bool // FreeIPA: has the fasGroup object class (freeipa-fas)
}

// NewUser is what a moderator approves into the directory.
type NewUser struct {
	Username  string
	GivenName string
	Surname   string
	Email     string
}

// Directory is everything SAM needs from LDAP.
type Directory interface {
	Ping(ctx context.Context) error
	GetUser(ctx context.Context, username string) (*User, error)
	FindUserByEmail(ctx context.Context, email string) (*User, error)
	SearchUsers(ctx context.Context, query string, limit int) ([]*User, error)
	CreateUser(ctx context.Context, u NewUser) error
	SetPassword(ctx context.Context, username, password string) error
	ChangePassword(ctx context.Context, username, oldPassword, newPassword string) error
	ExpirePassword(ctx context.Context, username string) error
	UpdateContact(ctx context.Context, username string, c Contact) error
	SetSSHKeys(ctx context.Context, username string, keys []string) error

	GetGroup(ctx context.Context, name string) (*Group, error)
	SearchGroups(ctx context.Context, query string, limit int) ([]*Group, error)
	CreateGroup(ctx context.Context, name, description, firstMember string) error
	DeleteGroup(ctx context.Context, name string) error
	SetGroupDescription(ctx context.Context, name, description string) error
	AddMember(ctx context.Context, group, username string) error
	RemoveMember(ctx context.Context, group, username string) error
	UserGroups(ctx context.Context, username string) ([]string, error)
}
