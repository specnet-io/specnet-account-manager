# Details

The rationale behind the code. Each code comment points to a section here.

## Environment

These settings are needed before the database opens: listen address, database URL, base URL, encryption key, trusted proxies and log level. They come only from the environment. Everything else is a runtime [setting](#settings). `SAM_BASE_URL` is required because emailed links and the OIDC redirect URI must not be derived from request headers, which a client can forge.

## Secrets

Nothing secret is stored in clear text:

| What | How it is stored |
|---|---|
| Settings of kind *secret* (LDAP bind password, OIDC client secret, Mailjet key/secret, SMTP password) | AES-256-GCM with `SAM_ENCRYPTION_KEY`; the setting name is the additional data, so a ciphertext cannot be moved to another setting |
| Queued emails (they can contain reset links) | sealed the same way; the body is dropped once sent |
| One-time tokens (verify, reset, email change, admin link) and session ids | SHA-256 hash only; the clear token exists only in the email or cookie |
| A pending new email address | sealed, bound to the username |
| OIDC state/nonce/PKCE verifier | sealed in a short-lived cookie |

Secrets set through `SAM_*` variables are held in memory only. `NAME_FILE=/path` reads a value from a mounted secret file. The admin page never shows a secret back: a blank field keeps the stored value, and "clear" removes it. The activity log records which settings changed, never their values.

Losing `SAM_ENCRYPTION_KEY` means re-entering the secret settings. Everything else keeps working: sessions, tokens and requests don't depend on it. Mail that is still queued is lost.

## Database

SQLite (pure Go, no cgo) by default; Postgres when `SAM_DATABASE_URL` starts with `postgres://`. The SQL is kept portable: text ids, integer unix timestamps, `?` placeholders rewritten to `$n` for Postgres, and `ON CONFLICT` upserts. SQLite runs in WAL mode with one connection, which is plenty for the expected load and avoids `SQLITE_BUSY`. Migrations are an ordered list in `store.go`, applied once each, and a newer schema refuses to start an older binary.

SAM's own tables hold only what the directory can't: requests, sessions, tokens, group ownership, the activity log, the mail outbox and settings. Users and group memberships are always read live from LDAP.

## Settings

Effective value, in order of precedence: `SAM_<NAME>` env (locked in the UI) > value saved on the admin page > built-in default. Every change bumps a version number so cached clients (the LDAP config and the OIDC provider) are rebuilt. All settings:

General: `site_name`, `support_email`, `account_requests_enabled`, `username_pattern`, `group_name_pattern`, `password_min_length`, `session_hours`, `audit_retention_days`.
Roles: `moderator_group`, `admin_group`.
OIDC: `oidc_issuer`, `oidc_client_id`, `oidc_client_secret`, `oidc_scopes`, `oidc_username_claim`, `oidc_match_attribute` (`username`|`email`), `oidc_strip_domain`.
LDAP: `ldap_profile` (`freeipa`|`openldap`), `ldap_url`, `ldap_starttls`, `ldap_ca_cert`, `ldap_insecure_skip_verify`, `ldap_bind_dn`, `ldap_bind_password`, `ldap_base_dn`, `ldap_user_base`, `ldap_group_base`, `ldap_fas_groups`, `ldap_kerberos_realm`, `ldap_ssh_key_attribute`, `ldap_id_min`, `ldap_home_prefix`, `ldap_login_shell`, `ldap_timeout_seconds`.
Notifications: `notify_provider` (`mailjet`|`smtp`|`log`|`none`), `mail_from_address`, `mail_from_name`, `mailjet_api_key`, `mailjet_api_secret`, `mailjet_api_url`, `smtp_host`, `smtp_port`, `smtp_security` (`starttls`|`tls`|`none`), `smtp_username`, `smtp_password`.
Profile: `editable_fields`, `ssh_key_types`, `ssh_rsa_min_bits`, `ssh_max_keys`, `gravatar_enabled`, `gravatar_default`.

## Directory

One interface (`directory.Directory`) and one LDAP implementation with two schema profiles. SAM opens a connection per operation: there is no pool to go stale, and the load is small. It binds as the service account, except when changing a user's own password, where it binds as that user.

- Users: `posixAccount` entries under the user base, looked up by `uid` (or `mail`).
- Groups: `groupOfNames` with DN-valued `member`. Only direct members are shown and changed. Nested groups are left alone.
- Roles: a user is a moderator or admin if they are a **direct** member of the configured group. Roles are re-read from LDAP every 5 minutes during a session, and a user who is removed or disabled in LDAP is signed out at that point.
- **Managed groups**: SAM only touches groups registered in its `managed_groups` table, either created through an approved request or adopted by a moderator. Owners are stored in SAM, not in LDAP, so ownership works the same on any directory. The moderator group and the admin group can never be managed, which keeps role assignment out of reach of moderators and group owners.
- **FAS groups only** (`ldap_fas_groups`, FreeIPA with the freeipa-fas plugin): SAM manages only groups with the `fasGroup` object class. Moderators' group search lists only FAS groups, adopting a non-FAS group is refused, and groups created from requests get `fasGroup`. The directory decides on every request: if `fasGroup` is removed from a managed group, it disappears from SAM's lists and its pages return 404, but stays registered, so adding `fasGroup` back restores it with its owners. This replaced the `protected_groups` list (removed): to keep SAM away from a group, leave it, or make it, a non-FAS group. freeipa-fas's `--fasgroup` flag only adds the class; to remove it, clear any `fas*` attributes and then run `ipa group-mod <group> --delattr=objectclass=fasgroup`. Ignored on the OpenLDAP profile.
- OpenLDAP profile: new users get `inetOrgPerson`+`posixAccount`, with `uidNumber` = `gidNumber` = highest number in use ≥ `ldap_id_min`, plus one. No per-user group is created. New groups are plain `groupOfNames`, so they need at least one member; the requester is the first one. SSH keys use `sshPublicKey` from the openssh-lpk schema, and SAM adds `ldapPublicKey` to the user when needed.

## FreeIPA

SAM writes to IPA over LDAP and relies on IPA's 389-DS plugins to do what `ipa user-add` would:
- `uidNumber`/`gidNumber: -1` → the DNA plugin allocates IDs
- `ipaUniqueID: autogenerate` → the UUID plugin
- `mepOriginEntry` → the managed-entries plugin creates the user private group
- `krbPrincipalName` is `uid@REALM` (realm from `ldap_kerberos_realm` or the base DN)
- new users are also added to `ipausers`

New groups get `ipausergroup`, `posixgroup` and `gidNumber: -1`.

Service account password: IPA user passwords expire (90 days by default). Either give `svc-sam` a far-future `krbPasswordExpiration` (as an admin: `ipa user-mod svc-sam --setattr krbPasswordExpiration=20991231000000Z`) or rotate it on schedule in the admin page.

**Not yet verified against a live IPA server**: the LDAP-only user creation and the [password](#passwords) sequence are tested against OpenLDAP, and the IPA attribute set follows IPA's own schema. Test both on a staging IPA before production use.

## Passwords

- **Change** (signed in): SAM binds as the user with their current password and sends an RFC 3062 password-modify as them. To the directory this is a normal self-service change.
- **Reset** (emailed link, new-account setup): an administrative set would leave an IPA password already expired, so the user would be forced to change it again at their next login. On the `freeipa` profile SAM therefore (1) sets a random throwaway password as the service account and then (2) changes it to the user's choice while bound as the user. On OpenLDAP it is a single administrative set. If your IPA has `svc-sam` in `passSyncManagersDNs`, administrative sets don't expire passwords, and the two steps still work.
- **Forced reset** (moderator): sets a random password, so the old one stops working right away. It also ends the user's SAM sessions and emails a 72-hour reset link.

The directory's own password policy always applies. SAM checks only a minimum length, matching confirmation, and that the password doesn't contain the username, then shows the directory's message if it rejects the password.

## Tokens

| Link | Lifetime | Use |
|---|---|---|
| Verify account request | 24 h | single |
| Forgot-password reset | 1 h | single; a new request replaces older links |
| New-account setup / forced reset | 72 h | single |
| Email change | 24 h | single |
| Admin setup link | 15 min (`-ttl`) | single |

Links that change something when opened (verify, confirm email, admin link) show a confirmation button and act on the POST. Mail scanners that pre-fetch links would otherwise use them up. Unconfirmed account requests expire after 48 hours.

## Sign-in

Authorization code flow with PKCE (S256), `state` and `nonce`. All three live in a sealed cookie valid for 10 minutes. The ID token is verified with the issuer's JWKS (go-oidc). The configured claim is matched to a directory account. If none matches, the user sees "no account" with a link to request one. Disabled accounts (`nsAccountLock`) can't sign in. Sessions are server-side: the cookie holds a random token and the table holds its hash. Sign-out ends the SAM session only, not the provider's.

## Bootstrap

`sam admin-link` writes a hashed single-use token straight into the database and prints a link. The link gives a one-hour session with only the admin role and no directory identity, so the first administrator can configure OIDC and LDAP before either works. Run it inside the container (`docker exec sam /sam admin-link`); it needs the same environment as the server.

## Notifications

Events are rendered from `internal/notify/templates/*.txt` (the first line is `Subject: ...`) into plain-text emails. Each recipient gets a separate, sealed outbox row. A background worker delivers them with exponential backoff and gives up after 8 attempts. Failures never block the action that caused the email, and the admin page shows queue counts and the last error. Providers: Mailjet Send API v3.1 (basic auth with the API key and secret), SMTP (STARTTLS, implicit TLS, or plain; credentials are refused over plain), `log` (logs only the subject: bodies may hold links) and `none`. Moderator notifications go to the email addresses of the moderator group's members.

## Gravatar

`https://gravatar.com/avatar/<sha256(lowercased email)>?s=..&d=<fallback>&r=g`. The browser loads the image directly. The CSP allows only the Gravatar hosts, and `Referrer-Policy: no-referrer` keeps page URLs, which may contain tokens, from leaking to Gravatar. Admins can turn it off.

## Web

Server-rendered `html/template` pages and one stylesheet, with no JavaScript. That lets the CSP be `default-src 'none'`. Every POST needs a CSRF token: the session's token, or a per-browser cookie before sign-in. A POST with an `Origin` header from another site is rejected. Cookies are `HttpOnly`, `SameSite=Lax`, and `Secure` with the `__Host-` prefix when the base URL is https. `X-Forwarded-For` is honoured only from `SAM_TRUSTED_PROXIES`, and the client IP is used for rate limits (account requests, password resets, password changes) and the activity log. Request bodies are capped at 256 KiB. `/healthz` is liveness and `/readyz` also checks the database.

## Theme

The specnet phosphor-green terminal look, the same as the authentik login (its brand files) and the noggin theme: `static/logo.svg` in the header, `static/icon.svg` as favicon, `static/background.svg` (dark grid) behind every page, monospace system fonts (no web fonts, so the CSP stays `img-src 'self'`-only for local files), square corners, outlined `[ button ]`s, and `[ OK ]`/`[FAIL]` flashes. Dark only. Scanlines and the blinking footer cursor are CSS; the cursor stops with `prefers-reduced-motion`. To rebrand, replace the three SVGs and the colour variables at the top of `static/app.css`.

## Container

Multi-stage build to a `scratch` image: the static binary, CA certificates and zoneinfo. It runs as uid 65532. `/data` must be writable by that uid, which a named volume is by default; for a bind mount, `chown 65532:65532` it. The healthcheck is `sam healthcheck`, since the image has no shell or curl.

## Testing

- `go test ./...`: unit tests, plus end-to-end tests of the whole web app with an in-memory directory, a recording mail sender and a fake OIDC provider that signs real RS256 ID tokens and checks PKCE.
- `test/integration.sh`: starts OpenLDAP (`osixia/openldap`, with the openssh-lpk schema loaded) and Postgres in containers. It runs the LDAP backend tests over LDAPS and over StartTLS, and the store tests against Postgres. CI runs both on every pull request and before every release.
