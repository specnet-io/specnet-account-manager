# Notes for agents

- Go 1.27, binary `sam`. Third-party modules are limited to: go-ldap, go-oidc + x/oauth2, x/crypto/ssh, modernc sqlite, pgx. Ask before adding more.
- Layout: `main.go` (env, serve, `admin-link`, `gen-key`, `healthcheck`), `internal/secret` (AES-GCM sealing, token hashing), `internal/store` (SQLite/Postgres, migrations), `internal/settings` (registry: default < DB < `SAM_*` env), `internal/directory` (interface + LDAP with `freeipa`/`openldap` profiles, SSH key parsing), `internal/auth` (OIDC), `internal/notify` (outbox, Mailjet, SMTP, text templates), `internal/web` (handlers, middleware, embedded templates/CSS), `internal/avatar`.
- Docs convention: code comments are one-liners pointing to `DETAILS.md §Section`; human docs are `README.md` (product, operation, versioning) and `DETAILS.md` (rationale). Keep AI notes here only.
- Never store a credential in clear: secret settings and outbox payloads go through `secret.Sealer`; tokens and session ids are stored as `secret.Hash`. Never log or audit a secret value or a mail body.
- LDAP is the source of truth. The store keeps only requests, sessions, tokens, managed groups/owners, audit, outbox, settings. Group actions must go through `loadManaged` (managed + not protected).
- New settings: add a `settings.Def`, then it appears on the admin page and as `SAM_<KEY>` automatically. Update the list in DETAILS.md §Settings.
- New notification: add `internal/notify/templates/<event>.txt` (first line `Subject: ...`); `TestAllTemplatesRender` checks it with a full data map, so add any new keys there.
- SQL must run on both SQLite and Postgres (`?` placeholders, no AUTOINCREMENT, `ON CONFLICT`). Add schema changes as new entries at the end of `migrations`; never edit old ones.
- Before pushing: `gofmt -l .`, `go vet ./...`, `go test -race ./...`, and `bash test/integration.sh` when touching `directory` or `store`. Run builds and tests on the sandbox VM, not the workstation.
- The FreeIPA profile has not been run against a live IPA server yet (see DETAILS.md §FreeIPA). Don't claim it works until it has been.
- Workflow: no direct pushes to `main`; open a PR. Merging to `main` auto-releases the next patch of `VERSION` to GitHub releases + ghcr.io.
