// Package store is SAM's own state (requests, sessions, tokens, ownership, audit, outbox) in SQLite or Postgres. See DETAILS.md §Database.
package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib" // postgres driver "pgx"
	_ "modernc.org/sqlite"             // pure-Go sqlite driver "sqlite"
)

// ErrNotFound is returned when a row does not exist.
var ErrNotFound = errors.New("not found")

// Store wraps the database and hides the SQLite/Postgres differences.
type Store struct {
	db       *sql.DB
	postgres bool
	now      func() time.Time
}

// Open connects to url: "sqlite:///path/sam.db", a bare file path, or "postgres://...".
func Open(ctx context.Context, url string) (*Store, error) {
	s := &Store{now: time.Now}
	var err error
	switch {
	case strings.HasPrefix(url, "postgres://"), strings.HasPrefix(url, "postgresql://"):
		s.postgres = true
		s.db, err = sql.Open("pgx", url)
		if err != nil {
			return nil, err
		}
		s.db.SetMaxOpenConns(8)
	default:
		path := strings.TrimPrefix(strings.TrimPrefix(url, "sqlite://"), "file:")
		if path == "" {
			return nil, errors.New("empty database path")
		}
		if path != ":memory:" {
			if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
				return nil, fmt.Errorf("database directory: %w", err)
			}
		}
		dsn := "file:" + path + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)&_pragma=synchronous(NORMAL)"
		s.db, err = sql.Open("sqlite", dsn)
		if err != nil {
			return nil, err
		}
		s.db.SetMaxOpenConns(1) // one writer; load is small. See DETAILS.md §Database.
	}
	if err := s.db.PingContext(ctx); err != nil {
		s.db.Close()
		return nil, fmt.Errorf("database: %w", err)
	}
	if err := s.migrate(ctx); err != nil {
		s.db.Close()
		return nil, fmt.Errorf("database migration: %w", err)
	}
	return s, nil
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

// Ping checks the database is reachable (readiness).
func (s *Store) Ping(ctx context.Context) error { return s.db.PingContext(ctx) }

// SetClock overrides the clock (tests).
func (s *Store) SetClock(f func() time.Time) { s.now = f }

// q rewrites ? placeholders to $n for Postgres.
func (s *Store) q(query string) string {
	if !s.postgres {
		return query
	}
	var b strings.Builder
	n := 0
	for _, r := range query {
		if r == '?' {
			n++
			b.WriteString("$" + strconv.Itoa(n))
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

func (s *Store) exec(ctx context.Context, query string, args ...any) (sql.Result, error) {
	return s.db.ExecContext(ctx, s.q(query), args...)
}

func (s *Store) queryRow(ctx context.Context, query string, args ...any) *sql.Row {
	return s.db.QueryRowContext(ctx, s.q(query), args...)
}

func (s *Store) query(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	return s.db.QueryContext(ctx, s.q(query), args...)
}

// NewID returns a random 128-bit hex id.
func NewID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

func (s *Store) unix() int64 { return s.now().Unix() }

func notFound(err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	return err
}

var migrations = []string{
	`CREATE TABLE settings (
		key TEXT PRIMARY KEY,
		value TEXT NOT NULL,
		updated_at BIGINT NOT NULL,
		updated_by TEXT NOT NULL
	)`,
	`CREATE TABLE sessions (
		id_hash TEXT PRIMARY KEY,
		username TEXT NOT NULL,
		display_name TEXT NOT NULL,
		email TEXT NOT NULL,
		roles TEXT NOT NULL,
		csrf TEXT NOT NULL,
		created_at BIGINT NOT NULL,
		expires_at BIGINT NOT NULL,
		refreshed_at BIGINT NOT NULL
	)`,
	`CREATE TABLE tokens (
		hash TEXT PRIMARY KEY,
		purpose TEXT NOT NULL,
		subject TEXT NOT NULL,
		data TEXT NOT NULL,
		created_at BIGINT NOT NULL,
		expires_at BIGINT NOT NULL
	)`,
	`CREATE INDEX tokens_subject ON tokens (purpose, subject)`,
	`CREATE TABLE account_requests (
		id TEXT PRIMARY KEY,
		username TEXT NOT NULL,
		given_name TEXT NOT NULL,
		surname TEXT NOT NULL,
		email TEXT NOT NULL,
		justification TEXT NOT NULL,
		status TEXT NOT NULL,
		created_at BIGINT NOT NULL,
		updated_at BIGINT NOT NULL,
		decided_by TEXT NOT NULL,
		decision_note TEXT NOT NULL
	)`,
	`CREATE INDEX account_requests_status ON account_requests (status)`,
	`CREATE TABLE group_requests (
		id TEXT PRIMARY KEY,
		name TEXT NOT NULL,
		description TEXT NOT NULL,
		justification TEXT NOT NULL,
		requester TEXT NOT NULL,
		status TEXT NOT NULL,
		created_at BIGINT NOT NULL,
		updated_at BIGINT NOT NULL,
		decided_by TEXT NOT NULL,
		decision_note TEXT NOT NULL
	)`,
	`CREATE TABLE join_requests (
		id TEXT PRIMARY KEY,
		group_name TEXT NOT NULL,
		username TEXT NOT NULL,
		note TEXT NOT NULL,
		status TEXT NOT NULL,
		created_at BIGINT NOT NULL,
		updated_at BIGINT NOT NULL,
		decided_by TEXT NOT NULL
	)`,
	`CREATE TABLE managed_groups (
		name TEXT PRIMARY KEY,
		created_at BIGINT NOT NULL,
		created_by TEXT NOT NULL
	)`,
	`CREATE TABLE group_owners (
		group_name TEXT NOT NULL,
		username TEXT NOT NULL,
		PRIMARY KEY (group_name, username)
	)`,
	`CREATE TABLE audit (
		id TEXT PRIMARY KEY,
		at BIGINT NOT NULL,
		actor TEXT NOT NULL,
		action TEXT NOT NULL,
		target TEXT NOT NULL,
		detail TEXT NOT NULL,
		ip TEXT NOT NULL
	)`,
	`CREATE INDEX audit_at ON audit (at)`,
	`CREATE TABLE outbox (
		id TEXT PRIMARY KEY,
		payload TEXT NOT NULL,
		status TEXT NOT NULL,
		attempts INTEGER NOT NULL,
		next_attempt BIGINT NOT NULL,
		last_error TEXT NOT NULL,
		created_at BIGINT NOT NULL,
		sent_at BIGINT NOT NULL
	)`,
	`CREATE INDEX outbox_due ON outbox (status, next_attempt)`,
}

func (s *Store) migrate(ctx context.Context) error {
	if _, err := s.exec(ctx, `CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL)`); err != nil {
		return err
	}
	var v int
	err := s.queryRow(ctx, `SELECT version FROM schema_version`).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		if _, err := s.exec(ctx, `INSERT INTO schema_version (version) VALUES (0)`); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	if v > len(migrations) {
		return fmt.Errorf("database schema version %d is newer than this build (%d)", v, len(migrations))
	}
	for i := v; i < len(migrations); i++ {
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, migrations[i]); err != nil {
			tx.Rollback()
			return fmt.Errorf("migration %d: %w", i+1, err)
		}
		if _, err := tx.ExecContext(ctx, s.q(`UPDATE schema_version SET version = ?`), i+1); err != nil {
			tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

// ---- settings ----

// AllSettings returns every stored setting (values as stored; secrets are still sealed).
func (s *Store) AllSettings(ctx context.Context) (map[string]string, error) {
	rows, err := s.query(ctx, `SELECT key, value FROM settings`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return nil, err
		}
		out[k] = v
	}
	return out, rows.Err()
}

// PutSetting upserts one setting.
func (s *Store) PutSetting(ctx context.Context, key, value, by string) error {
	_, err := s.exec(ctx, `INSERT INTO settings (key, value, updated_at, updated_by) VALUES (?, ?, ?, ?)
		ON CONFLICT (key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at, updated_by = excluded.updated_by`,
		key, value, s.unix(), by)
	return err
}

// DeleteSetting removes a setting so its default applies again.
func (s *Store) DeleteSetting(ctx context.Context, key string) error {
	_, err := s.exec(ctx, `DELETE FROM settings WHERE key = ?`, key)
	return err
}

// ---- sessions ----

// Session is a signed-in browser session. The cookie holds the token; the table holds its hash.
type Session struct {
	IDHash      string
	Username    string
	DisplayName string
	Email       string
	Roles       []string
	CSRF        string
	CreatedAt   time.Time
	ExpiresAt   time.Time
	RefreshedAt time.Time
}

// HasRole reports whether the session carries role r.
func (s *Session) HasRole(r string) bool {
	for _, x := range s.Roles {
		if x == r {
			return true
		}
	}
	return false
}

// CreateSession stores a session.
func (s *Store) CreateSession(ctx context.Context, se *Session) error {
	_, err := s.exec(ctx, `INSERT INTO sessions (id_hash, username, display_name, email, roles, csrf, created_at, expires_at, refreshed_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		se.IDHash, se.Username, se.DisplayName, se.Email, strings.Join(se.Roles, ","), se.CSRF,
		se.CreatedAt.Unix(), se.ExpiresAt.Unix(), se.RefreshedAt.Unix())
	return err
}

// GetSession loads an unexpired session by hash.
func (s *Store) GetSession(ctx context.Context, idHash string) (*Session, error) {
	se := &Session{}
	var roles string
	var c, e, r int64
	err := s.queryRow(ctx, `SELECT id_hash, username, display_name, email, roles, csrf, created_at, expires_at, refreshed_at
		FROM sessions WHERE id_hash = ? AND expires_at > ?`, idHash, s.unix()).
		Scan(&se.IDHash, &se.Username, &se.DisplayName, &se.Email, &roles, &se.CSRF, &c, &e, &r)
	if err != nil {
		return nil, notFound(err)
	}
	if roles != "" {
		se.Roles = strings.Split(roles, ",")
	}
	se.CreatedAt, se.ExpiresAt, se.RefreshedAt = time.Unix(c, 0), time.Unix(e, 0), time.Unix(r, 0)
	return se, nil
}

// RefreshSession rewrites a session's identity/roles after a directory re-check.
func (s *Store) RefreshSession(ctx context.Context, se *Session) error {
	_, err := s.exec(ctx, `UPDATE sessions SET display_name = ?, email = ?, roles = ?, refreshed_at = ? WHERE id_hash = ?`,
		se.DisplayName, se.Email, strings.Join(se.Roles, ","), se.RefreshedAt.Unix(), se.IDHash)
	return err
}

// DeleteSession signs a session out.
func (s *Store) DeleteSession(ctx context.Context, idHash string) error {
	_, err := s.exec(ctx, `DELETE FROM sessions WHERE id_hash = ?`, idHash)
	return err
}

// DeleteUserSessions signs a user out everywhere (forced reset).
func (s *Store) DeleteUserSessions(ctx context.Context, username string) error {
	_, err := s.exec(ctx, `DELETE FROM sessions WHERE username = ?`, username)
	return err
}

// ---- tokens ----

// Token purposes.
const (
	PurposeVerifyRequest = "verify_request" // subject: account request id
	PurposePassword      = "password"       // subject: username
	PurposeEmailChange   = "email_change"   // subject: username, data: sealed new address
	PurposeAdminLink     = "admin_link"     // subject: "bootstrap"
)

// Token is a stored one-time token (hash only).
type Token struct {
	Hash      string
	Purpose   string
	Subject   string
	Data      string
	ExpiresAt time.Time
}

// PutToken stores a token hash. If replace is set, older tokens with the same purpose+subject are dropped.
func (s *Store) PutToken(ctx context.Context, t *Token, replace bool) error {
	if replace {
		if _, err := s.exec(ctx, `DELETE FROM tokens WHERE purpose = ? AND subject = ?`, t.Purpose, t.Subject); err != nil {
			return err
		}
	}
	_, err := s.exec(ctx, `INSERT INTO tokens (hash, purpose, subject, data, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)`,
		t.Hash, t.Purpose, t.Subject, t.Data, s.unix(), t.ExpiresAt.Unix())
	return err
}

// PeekToken returns an unexpired token without consuming it.
func (s *Store) PeekToken(ctx context.Context, hash, purpose string) (*Token, error) {
	t := &Token{}
	var e int64
	err := s.queryRow(ctx, `SELECT hash, purpose, subject, data, expires_at FROM tokens WHERE hash = ? AND purpose = ? AND expires_at > ?`,
		hash, purpose, s.unix()).Scan(&t.Hash, &t.Purpose, &t.Subject, &t.Data, &e)
	if err != nil {
		return nil, notFound(err)
	}
	t.ExpiresAt = time.Unix(e, 0)
	return t, nil
}

// TakeToken consumes an unexpired token (single use).
func (s *Store) TakeToken(ctx context.Context, hash, purpose string) (*Token, error) {
	t, err := s.PeekToken(ctx, hash, purpose)
	if err != nil {
		return nil, err
	}
	res, err := s.exec(ctx, `DELETE FROM tokens WHERE hash = ?`, hash)
	if err != nil {
		return nil, err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return nil, ErrNotFound // raced with another use
	}
	return t, nil
}

// DeleteTokens removes all tokens for purpose+subject.
func (s *Store) DeleteTokens(ctx context.Context, purpose, subject string) error {
	_, err := s.exec(ctx, `DELETE FROM tokens WHERE purpose = ? AND subject = ?`, purpose, subject)
	return err
}

// ---- account requests ----

// Account request statuses.
const (
	StatusUnverified = "unverified"
	StatusPending    = "pending"
	StatusApproved   = "approved"
	StatusDenied     = "denied"
	StatusExpired    = "expired"
	StatusCancelled  = "cancelled"
)

// AccountRequest is a request for a new directory account.
type AccountRequest struct {
	ID            string
	Username      string
	GivenName     string
	Surname       string
	Email         string
	Justification string
	Status        string
	CreatedAt     time.Time
	UpdatedAt     time.Time
	DecidedBy     string
	DecisionNote  string
}

const accountCols = `id, username, given_name, surname, email, justification, status, created_at, updated_at, decided_by, decision_note`

func scanAccount(sc interface{ Scan(...any) error }) (*AccountRequest, error) {
	r := &AccountRequest{}
	var c, u int64
	if err := sc.Scan(&r.ID, &r.Username, &r.GivenName, &r.Surname, &r.Email, &r.Justification, &r.Status, &c, &u, &r.DecidedBy, &r.DecisionNote); err != nil {
		return nil, notFound(err)
	}
	r.CreatedAt, r.UpdatedAt = time.Unix(c, 0), time.Unix(u, 0)
	return r, nil
}

// CreateAccountRequest stores a new request.
func (s *Store) CreateAccountRequest(ctx context.Context, r *AccountRequest) error {
	if r.ID == "" {
		r.ID = NewID()
	}
	now := s.unix()
	r.CreatedAt, r.UpdatedAt = time.Unix(now, 0), time.Unix(now, 0)
	_, err := s.exec(ctx, `INSERT INTO account_requests (`+accountCols+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		r.ID, r.Username, r.GivenName, r.Surname, r.Email, r.Justification, r.Status, now, now, r.DecidedBy, r.DecisionNote)
	return err
}

// GetAccountRequest loads one request.
func (s *Store) GetAccountRequest(ctx context.Context, id string) (*AccountRequest, error) {
	return scanAccount(s.queryRow(ctx, `SELECT `+accountCols+` FROM account_requests WHERE id = ?`, id))
}

// ListAccountRequests lists requests with the given status, oldest first (all if status is "").
func (s *Store) ListAccountRequests(ctx context.Context, status string, limit int) ([]*AccountRequest, error) {
	query, args := `SELECT `+accountCols+` FROM account_requests`, []any{}
	if status != "" {
		query += ` WHERE status = ?`
		args = append(args, status)
		query += ` ORDER BY created_at ASC`
	} else {
		query += ` ORDER BY created_at DESC`
	}
	query += ` LIMIT ?`
	args = append(args, limit)
	rows, err := s.query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*AccountRequest
	for rows.Next() {
		r, err := scanAccount(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// OpenAccountRequestFor reports whether a live (unverified/pending) request holds the username or email.
func (s *Store) OpenAccountRequestFor(ctx context.Context, username, email string) (bool, error) {
	var n int
	err := s.queryRow(ctx, `SELECT COUNT(*) FROM account_requests WHERE status IN ('unverified','pending') AND (LOWER(username) = LOWER(?) OR LOWER(email) = LOWER(?))`,
		username, email).Scan(&n)
	return n > 0, err
}

// SetAccountRequestStatus moves a request from one status to another; ErrNotFound if it was not in `from`.
func (s *Store) SetAccountRequestStatus(ctx context.Context, id, from, to, by, note string) error {
	res, err := s.exec(ctx, `UPDATE account_requests SET status = ?, updated_at = ?, decided_by = ?, decision_note = ? WHERE id = ? AND status = ?`,
		to, s.unix(), by, note, id, from)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return ErrNotFound
	}
	return nil
}

// ExpireUnverifiedRequests marks unverified requests older than age as expired.
func (s *Store) ExpireUnverifiedRequests(ctx context.Context, age time.Duration) (int64, error) {
	res, err := s.exec(ctx, `UPDATE account_requests SET status = 'expired', updated_at = ? WHERE status = 'unverified' AND created_at < ?`,
		s.unix(), s.now().Add(-age).Unix())
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// ---- group requests ----

// GroupRequest asks moderators to create a new security group.
type GroupRequest struct {
	ID            string
	Name          string
	Description   string
	Justification string
	Requester     string
	Status        string
	CreatedAt     time.Time
	UpdatedAt     time.Time
	DecidedBy     string
	DecisionNote  string
}

const groupReqCols = `id, name, description, justification, requester, status, created_at, updated_at, decided_by, decision_note`

func scanGroupReq(sc interface{ Scan(...any) error }) (*GroupRequest, error) {
	r := &GroupRequest{}
	var c, u int64
	if err := sc.Scan(&r.ID, &r.Name, &r.Description, &r.Justification, &r.Requester, &r.Status, &c, &u, &r.DecidedBy, &r.DecisionNote); err != nil {
		return nil, notFound(err)
	}
	r.CreatedAt, r.UpdatedAt = time.Unix(c, 0), time.Unix(u, 0)
	return r, nil
}

// CreateGroupRequest stores a new group request.
func (s *Store) CreateGroupRequest(ctx context.Context, r *GroupRequest) error {
	if r.ID == "" {
		r.ID = NewID()
	}
	now := s.unix()
	r.CreatedAt, r.UpdatedAt = time.Unix(now, 0), time.Unix(now, 0)
	_, err := s.exec(ctx, `INSERT INTO group_requests (`+groupReqCols+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		r.ID, r.Name, r.Description, r.Justification, r.Requester, r.Status, now, now, r.DecidedBy, r.DecisionNote)
	return err
}

// GetGroupRequest loads one group request.
func (s *Store) GetGroupRequest(ctx context.Context, id string) (*GroupRequest, error) {
	return scanGroupReq(s.queryRow(ctx, `SELECT `+groupReqCols+` FROM group_requests WHERE id = ?`, id))
}

// ListGroupRequests lists group requests filtered by status and/or requester ("" = any).
func (s *Store) ListGroupRequests(ctx context.Context, status, requester string, limit int) ([]*GroupRequest, error) {
	query := `SELECT ` + groupReqCols + ` FROM group_requests WHERE 1=1`
	var args []any
	if status != "" {
		query += ` AND status = ?`
		args = append(args, status)
	}
	if requester != "" {
		query += ` AND requester = ?`
		args = append(args, requester)
	}
	query += ` ORDER BY created_at DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*GroupRequest
	for rows.Next() {
		r, err := scanGroupReq(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// PendingGroupRequestFor reports whether a pending request already exists for this group name.
func (s *Store) PendingGroupRequestFor(ctx context.Context, name string) (bool, error) {
	var n int
	err := s.queryRow(ctx, `SELECT COUNT(*) FROM group_requests WHERE status = 'pending' AND LOWER(name) = LOWER(?)`, name).Scan(&n)
	return n > 0, err
}

// SetGroupRequestStatus moves a pending group request to a decision.
func (s *Store) SetGroupRequestStatus(ctx context.Context, id, from, to, by, note string) error {
	res, err := s.exec(ctx, `UPDATE group_requests SET status = ?, updated_at = ?, decided_by = ?, decision_note = ? WHERE id = ? AND status = ?`,
		to, s.unix(), by, note, id, from)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return ErrNotFound
	}
	return nil
}

// ---- join requests ----

// JoinRequest asks a group's owners to add the requester.
type JoinRequest struct {
	ID        string
	GroupName string
	Username  string
	Note      string
	Status    string
	CreatedAt time.Time
	UpdatedAt time.Time
	DecidedBy string
}

const joinCols = `id, group_name, username, note, status, created_at, updated_at, decided_by`

func scanJoin(sc interface{ Scan(...any) error }) (*JoinRequest, error) {
	r := &JoinRequest{}
	var c, u int64
	if err := sc.Scan(&r.ID, &r.GroupName, &r.Username, &r.Note, &r.Status, &c, &u, &r.DecidedBy); err != nil {
		return nil, notFound(err)
	}
	r.CreatedAt, r.UpdatedAt = time.Unix(c, 0), time.Unix(u, 0)
	return r, nil
}

// CreateJoinRequest stores a join request.
func (s *Store) CreateJoinRequest(ctx context.Context, r *JoinRequest) error {
	if r.ID == "" {
		r.ID = NewID()
	}
	now := s.unix()
	r.CreatedAt, r.UpdatedAt = time.Unix(now, 0), time.Unix(now, 0)
	_, err := s.exec(ctx, `INSERT INTO join_requests (`+joinCols+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		r.ID, r.GroupName, r.Username, r.Note, r.Status, now, now, r.DecidedBy)
	return err
}

// GetJoinRequest loads one join request.
func (s *Store) GetJoinRequest(ctx context.Context, id string) (*JoinRequest, error) {
	return scanJoin(s.queryRow(ctx, `SELECT `+joinCols+` FROM join_requests WHERE id = ?`, id))
}

// ListJoinRequests lists join requests filtered by group, user and status ("" = any).
func (s *Store) ListJoinRequests(ctx context.Context, group, username, status string) ([]*JoinRequest, error) {
	query := `SELECT ` + joinCols + ` FROM join_requests WHERE 1=1`
	var args []any
	if group != "" {
		query += ` AND group_name = ?`
		args = append(args, group)
	}
	if username != "" {
		query += ` AND username = ?`
		args = append(args, username)
	}
	if status != "" {
		query += ` AND status = ?`
		args = append(args, status)
	}
	query += ` ORDER BY created_at DESC LIMIT 500`
	rows, err := s.query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*JoinRequest
	for rows.Next() {
		r, err := scanJoin(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// SetJoinRequestStatus moves a pending join request to a decision.
func (s *Store) SetJoinRequestStatus(ctx context.Context, id, from, to, by string) error {
	res, err := s.exec(ctx, `UPDATE join_requests SET status = ?, updated_at = ?, decided_by = ? WHERE id = ? AND status = ?`,
		to, s.unix(), by, id, from)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return ErrNotFound
	}
	return nil
}

// ---- managed groups and owners ----

// ManagedGroup is a directory group SAM is allowed to manage.
type ManagedGroup struct {
	Name      string
	CreatedAt time.Time
	CreatedBy string
	Owners    []string
}

// AddManagedGroup registers a group (and its first owner, if given).
func (s *Store) AddManagedGroup(ctx context.Context, name, by, owner string) error {
	if _, err := s.exec(ctx, `INSERT INTO managed_groups (name, created_at, created_by) VALUES (?, ?, ?) ON CONFLICT (name) DO NOTHING`,
		name, s.unix(), by); err != nil {
		return err
	}
	if owner != "" {
		return s.AddOwner(ctx, name, owner)
	}
	return nil
}

// RemoveManagedGroup unregisters a group and drops its owners and open join requests.
func (s *Store) RemoveManagedGroup(ctx context.Context, name string) error {
	for _, q := range []string{
		`DELETE FROM group_owners WHERE group_name = ?`,
		`UPDATE join_requests SET status = 'cancelled' WHERE group_name = ? AND status = 'pending'`,
		`DELETE FROM managed_groups WHERE name = ?`,
	} {
		if _, err := s.exec(ctx, q, name); err != nil {
			return err
		}
	}
	return nil
}

// GetManagedGroup loads a managed group with its owners.
func (s *Store) GetManagedGroup(ctx context.Context, name string) (*ManagedGroup, error) {
	g := &ManagedGroup{}
	var c int64
	if err := s.queryRow(ctx, `SELECT name, created_at, created_by FROM managed_groups WHERE name = ?`, name).Scan(&g.Name, &c, &g.CreatedBy); err != nil {
		return nil, notFound(err)
	}
	g.CreatedAt = time.Unix(c, 0)
	owners, err := s.Owners(ctx, name)
	g.Owners = owners
	return g, err
}

// ListManagedGroups returns every managed group with owners, sorted by name.
func (s *Store) ListManagedGroups(ctx context.Context) ([]*ManagedGroup, error) {
	rows, err := s.query(ctx, `SELECT name, created_at, created_by FROM managed_groups ORDER BY name`)
	if err != nil {
		return nil, err
	}
	var out []*ManagedGroup
	for rows.Next() {
		g := &ManagedGroup{}
		var c int64
		if err := rows.Scan(&g.Name, &c, &g.CreatedBy); err != nil {
			rows.Close()
			return nil, err
		}
		g.CreatedAt = time.Unix(c, 0)
		out = append(out, g)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	all, err := s.allOwners(ctx)
	if err != nil {
		return nil, err
	}
	for _, g := range out {
		g.Owners = all[g.Name]
	}
	return out, nil
}

func (s *Store) allOwners(ctx context.Context) (map[string][]string, error) {
	rows, err := s.query(ctx, `SELECT group_name, username FROM group_owners ORDER BY username`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string][]string{}
	for rows.Next() {
		var g, u string
		if err := rows.Scan(&g, &u); err != nil {
			return nil, err
		}
		out[g] = append(out[g], u)
	}
	return out, rows.Err()
}

// Owners lists a group's owners.
func (s *Store) Owners(ctx context.Context, group string) ([]string, error) {
	rows, err := s.query(ctx, `SELECT username FROM group_owners WHERE group_name = ? ORDER BY username`, group)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var u string
		if err := rows.Scan(&u); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// OwnedGroups lists the groups a user owns.
func (s *Store) OwnedGroups(ctx context.Context, username string) ([]string, error) {
	rows, err := s.query(ctx, `SELECT group_name FROM group_owners WHERE username = ? ORDER BY group_name`, username)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var g string
		if err := rows.Scan(&g); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

// IsOwner reports whether username owns group.
func (s *Store) IsOwner(ctx context.Context, group, username string) (bool, error) {
	var n int
	err := s.queryRow(ctx, `SELECT COUNT(*) FROM group_owners WHERE group_name = ? AND username = ?`, group, username).Scan(&n)
	return n > 0, err
}

// AddOwner makes username an owner of group.
func (s *Store) AddOwner(ctx context.Context, group, username string) error {
	_, err := s.exec(ctx, `INSERT INTO group_owners (group_name, username) VALUES (?, ?) ON CONFLICT (group_name, username) DO NOTHING`, group, username)
	return err
}

// RemoveOwner drops username as an owner of group.
func (s *Store) RemoveOwner(ctx context.Context, group, username string) error {
	_, err := s.exec(ctx, `DELETE FROM group_owners WHERE group_name = ? AND username = ?`, group, username)
	return err
}

// TransferOwnership replaces all owners of group with newOwner.
func (s *Store) TransferOwnership(ctx context.Context, group, newOwner string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, s.q(`DELETE FROM group_owners WHERE group_name = ?`), group); err != nil {
		tx.Rollback()
		return err
	}
	if _, err := tx.ExecContext(ctx, s.q(`INSERT INTO group_owners (group_name, username) VALUES (?, ?)`), group, newOwner); err != nil {
		tx.Rollback()
		return err
	}
	return tx.Commit()
}

// ---- audit ----

// AuditEntry is one line of the activity log.
type AuditEntry struct {
	ID     string
	At     time.Time
	Actor  string
	Action string
	Target string
	Detail string
	IP     string
}

// Audit appends to the activity log; failures are returned but callers usually only log them.
func (s *Store) Audit(ctx context.Context, actor, action, target, detail, ip string) error {
	_, err := s.exec(ctx, `INSERT INTO audit (id, at, actor, action, target, detail, ip) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		NewID(), s.now().UnixMilli(), actor, action, target, detail, ip)
	return err
}

// ListAudit returns the newest entries first, optionally filtered by a substring of actor/target/action.
func (s *Store) ListAudit(ctx context.Context, filter string, limit int) ([]*AuditEntry, error) {
	query := `SELECT id, at, actor, action, target, detail, ip FROM audit`
	var args []any
	if filter != "" {
		query += ` WHERE actor LIKE ? OR target LIKE ? OR action LIKE ?`
		f := "%" + filter + "%"
		args = append(args, f, f, f)
	}
	query += ` ORDER BY at DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*AuditEntry
	for rows.Next() {
		e := &AuditEntry{}
		var at int64
		if err := rows.Scan(&e.ID, &at, &e.Actor, &e.Action, &e.Target, &e.Detail, &e.IP); err != nil {
			return nil, err
		}
		e.At = time.UnixMilli(at)
		out = append(out, e)
	}
	return out, rows.Err()
}

// ---- outbox ----

// OutboxItem is a queued notification; Payload is sealed (it can carry reset links).
type OutboxItem struct {
	ID       string
	Payload  string
	Attempts int
}

// Enqueue adds a sealed notification payload to the outbox.
func (s *Store) Enqueue(ctx context.Context, payload string) error {
	now := s.unix()
	_, err := s.exec(ctx, `INSERT INTO outbox (id, payload, status, attempts, next_attempt, last_error, created_at, sent_at) VALUES (?, ?, 'queued', 0, ?, '', ?, 0)`,
		NewID(), payload, now, now)
	return err
}

// DueOutbox returns queued items whose next attempt is due.
func (s *Store) DueOutbox(ctx context.Context, limit int) ([]*OutboxItem, error) {
	rows, err := s.query(ctx, `SELECT id, payload, attempts FROM outbox WHERE status = 'queued' AND next_attempt <= ? ORDER BY created_at LIMIT ?`, s.unix(), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*OutboxItem
	for rows.Next() {
		it := &OutboxItem{}
		if err := rows.Scan(&it.ID, &it.Payload, &it.Attempts); err != nil {
			return nil, err
		}
		out = append(out, it)
	}
	return out, rows.Err()
}

// MarkSent records a delivered item and drops its payload (no need to keep links around).
func (s *Store) MarkSent(ctx context.Context, id string) error {
	_, err := s.exec(ctx, `UPDATE outbox SET status = 'sent', payload = '', sent_at = ?, last_error = '' WHERE id = ?`, s.unix(), id)
	return err
}

// MarkFailed records a failed attempt; after maxAttempts the item is given up on.
func (s *Store) MarkFailed(ctx context.Context, id string, attempts, maxAttempts int, next time.Time, errText string) error {
	status := "queued"
	if attempts >= maxAttempts {
		status = "failed"
	}
	if len(errText) > 500 {
		errText = errText[:500]
	}
	_, err := s.exec(ctx, `UPDATE outbox SET status = ?, attempts = ?, next_attempt = ?, last_error = ? WHERE id = ?`,
		status, attempts, next.Unix(), errText, id)
	return err
}

// OutboxStats counts outbox items by status (admin page).
func (s *Store) OutboxStats(ctx context.Context) (map[string]int, error) {
	rows, err := s.query(ctx, `SELECT status, COUNT(*) FROM outbox GROUP BY status`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var st string
		var n int
		if err := rows.Scan(&st, &n); err != nil {
			return nil, err
		}
		out[st] = n
	}
	return out, rows.Err()
}

// LastOutboxError returns the most recent failure text, if any.
func (s *Store) LastOutboxError(ctx context.Context) (string, error) {
	var e string
	err := s.queryRow(ctx, `SELECT last_error FROM outbox WHERE last_error <> '' ORDER BY created_at DESC LIMIT 1`).Scan(&e)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return e, err
}

// Cleanup removes expired sessions/tokens, old sent mail and audit rows past retention.
func (s *Store) Cleanup(ctx context.Context, auditRetention time.Duration) error {
	now := s.unix()
	stmts := []struct {
		q    string
		args []any
	}{
		{`DELETE FROM sessions WHERE expires_at <= ?`, []any{now}},
		{`DELETE FROM tokens WHERE expires_at <= ?`, []any{now}},
		{`DELETE FROM outbox WHERE status IN ('sent','failed') AND created_at < ?`, []any{now - 30*86400}},
	}
	if auditRetention > 0 {
		stmts = append(stmts, struct {
			q    string
			args []any
		}{`DELETE FROM audit WHERE at < ?`, []any{s.now().Add(-auditRetention).UnixMilli()}})
	}
	for _, st := range stmts {
		if _, err := s.exec(ctx, st.q, st.args...); err != nil {
			return err
		}
	}
	return nil
}
