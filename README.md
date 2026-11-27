# specnet-account-manager (SAM)

Self-service accounts and groups for LDAP directories, with single sign-on.

Your directory (FreeIPA, or OpenLDAP) stays the source of truth. People sign in to SAM with your OIDC provider (Keycloak, Authentik, Entra ID, Google…), and SAM makes the changes in LDAP on their behalf.

## What it does

**Everyone with an account**
- update their contact details (name, email, phone, title); email changes are confirmed by a link
- change their password, or reset a forgotten one by email
- add and remove SSH public keys (type and RSA size rules are configurable)
- see their groups, ask to join groups, leave groups
- ask for a new security group; once approved they own it and manage its members
- Gravatar profile pictures, from their email address

**People without an account** can request one. They confirm their email address, a moderator approves the request, and they get a link to choose a password.

**Moderators** (members of a directory group, `sam-moderators` by default)
- approve or deny account requests and group requests
- manage every group SAM manages: members, owners, transfer ownership, delete
- bring existing directory groups under management
- force a password reset (the old password stops working; the user is emailed a link)

**Administrators** (a separate group, `sam-admins` by default) configure the application itself from the **Administration** page: sign-in, directory connection, notifications, roles and policies.

Every event that matters sends an email: request received, approved or denied, password changed, SSH key added, membership changed, and so on. Mail goes through the **Mailjet API** by default, or **SMTP**. Everything is written to an activity log that moderators and administrators can read.

## Run it

SAM is a single container listening on plain HTTP port 8080. Put it behind your load balancer or reverse proxy for TLS.

```sh
# 1. a key that encrypts every secret SAM stores; keep it safe, losing it means re-entering secrets
docker run --rm ghcr.io/specnet-io/specnet-account-manager:latest gen-key > sam_encryption_key

# 2. run
docker run -d --name sam -p 127.0.0.1:8080:8080 \
  -e SAM_BASE_URL=https://accounts.example.com \
  -e SAM_TRUSTED_PROXIES=10.0.0.0/8 \
  -e SAM_ENCRYPTION_KEY_FILE=/run/secrets/key -v "$PWD/sam_encryption_key:/run/secrets/key:ro" \
  -v sam-data:/data \
  ghcr.io/specnet-io/specnet-account-manager:latest

# 3. first sign-in: a one-time link to the Administration page (valid 15 minutes)
docker exec sam /sam admin-link
```

Open the link, then fill in **Sign-in (OIDC)** and **Directory (LDAP)**. Use the test buttons on each section. After that, people in the administrator group sign in normally. A compose file is in [deploy/compose.yaml](deploy/compose.yaml).

### Environment

| Variable | Default | |
|---|---|---|
| `SAM_BASE_URL` | (required) | Public URL, e.g. `https://accounts.example.com`. Used for links in emails and the OIDC redirect URI (`<base>/auth/callback`). |
| `SAM_ENCRYPTION_KEY` | (required) | 32-byte key, base64 or hex (`sam gen-key`). Encrypts secrets, mail and sign-in state at rest. |
| `SAM_DATABASE_URL` | `sqlite:///data/sam.db` | Or `postgres://user:pass@host/db`. |
| `SAM_TRUSTED_PROXIES` | (none) | Comma-separated IPs/CIDRs allowed to set `X-Forwarded-For`. |
| `SAM_DATA_DIR` | `/data` | Where the SQLite file lives. |
| `SAM_LISTEN` | `:8080` | |
| `SAM_LOG_LEVEL` | `info` | `debug`, `info`, `warn`, `error`. Logs are JSON on stdout. |

Any setting on the Administration page can also be pinned with `SAM_<NAME>`, e.g. `SAM_OIDC_ISSUER`, `SAM_LDAP_BIND_PASSWORD`, `SAM_MAILJET_API_SECRET`. A pinned setting is read-only on the page. Every variable also accepts `<NAME>_FILE=/path`, for Docker, Kubernetes or Nomad secrets. The full list of settings is in [DETAILS.md](DETAILS.md#settings).

### Sign-in provider

Create a confidential OIDC client (a public client also works, since PKCE is always used):
- redirect URI: `https://<your SAM host>/auth/callback`
- scopes: `openid profile email`

By default SAM matches the `preferred_username` claim to the directory `uid`. You can match on another claim, or on email instead.

### Directory service account

SAM binds to LDAP with one service account, and it needs rights to create and modify users and groups and to reset passwords. On FreeIPA:

```sh
ipa user-add svc-sam --first=SAM --last=Service --password
ipa role-add "SAM service"
ipa role-add-privilege "SAM service" --privileges="User Administrators" --privileges="Group Administrators"
ipa role-add-member "SAM service" --users=svc-sam
ipa group-add sam-moderators && ipa group-add sam-admins
```

Then set **Service account DN** to `uid=svc-sam,cn=users,cn=accounts,dc=example,dc=com` and **Base DN** to `dc=example,dc=com`. [DETAILS.md](DETAILS.md#freeipa) covers password expiry for this account and how resets behave.

## Versioning and releases

- Versions are semver tags `vMAJOR.MINOR.PATCH`. The [VERSION](VERSION) file holds `MAJOR.MINOR`.
- Changes reach `main` only through pull requests. CI runs formatting, vet, unit tests, integration tests against real OpenLDAP and Postgres, govulncheck, and a container build.
- Every merge to `main` runs the tests again. If they pass, the next patch version is released automatically: a git tag, a GitHub release with generated notes, and the image `ghcr.io/specnet-io/specnet-account-manager` tagged `X.Y.Z`, `X.Y` and `latest`.
- To start a new minor or major series, change `VERSION` in a pull request (e.g. `0.2`). The next merge releases `v0.2.0`.

## Development

```sh
go test -race ./...                  # unit + end-to-end web tests (fake directory and OIDC provider)
bash test/integration.sh             # real OpenLDAP + Postgres in containers (needs docker)
```

## License

MIT
