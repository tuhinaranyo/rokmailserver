# rokmail — build spec

Minimal self-hosted mail for rokomari.com: 300–1,000 small mailboxes, role
(shared) addresses, a tiny role-based admin panel. No Mailu/mailcow: plain
Postfix + Dovecot + Rspamd, glued by one SQLite file that a small Go admin app
owns. Target: whole stack idle under ~400 MB RAM on a 2–4 vCPU VPS.

## Layout

```
admin/      Go admin app (module `rokmail`), embeds schema.sql + templates
  schema.sql   DB CONTRACT — already written, do not rename columns/views
deploy/     docker-compose.yml, .env.example, Caddyfile
  mail/        Dockerfile + entrypoint + Postfix/Dovecot config (one container)
  rspamd/      local.d overrides
scripts/    backup.sh, smoke test
docs/       SPEC.md (this), SETUP.md (DNS, install, migration, operations)
```

## Services (docker compose)

| Service | Image | Role |
|---|---|---|
| `mail` | own, `ubuntu:24.04` (Postfix 3.8, **Dovecot 2.3** syntax — do not move to a base with Dovecot 2.4) | SMTP 25/465/587, IMAPS 993, LMTP, SASL, sieve, postsrsd |
| `rspamd` | `rspamd/rspamd` pinned tag | spam filter via milter, DKIM signing, outbound ratelimit |
| `redis` | `valkey/valkey:8-alpine` (or redis alpine), maxmemory 64mb | rspamd state |
| `admin` | own, multi-stage Go → distroless/static or scratch | admin panel on :8080 |
| `caddy` | `caddy:2-alpine` | HTTPS + ACME cert for `MAIL_HOST`, proxies admin (+ webmail) |
| `webmail` | `roundcube/roundcubemail` — compose **profile `webmail`**, off by default | optional webmail at `/webmail` or own path |

No ClamAV, no POP3, no port 143, no MySQL/Postgres.

Volumes: `db` (admin rw, mail rw), `dkim` (admin rw, rspamd ro), `maildata`
(mail), `caddy_data` (caddy rw, mail ro), `rspamd_data`, `redis_data`,
`postfix_spool`.

### Shared SQLite rules
- File `/db/mail.db`, WAL mode. Admin is the only writer.
- Readers in another container must be able to create `-shm`/`-wal`, so admin
  creates the dir `0777` and db files `0666` (umask 0). The volume is private
  to `admin` and `mail`; that is the access control.
- Postfix uses `proxy:sqlite:` maps, no chroot (set chroot `n` in master.cf).
- Mail flow must keep working when the `admin` container is stopped.

### `.env` (deploy/.env.example)
`MAIL_HOST` (mail.rokomari.com), `PRIMARY_DOMAIN` (rokomari.com),
`ADMIN_EMAIL`, `ADMIN_PASSWORD` (bootstrap superadmin, first run only),
`RELAYHOST` (e.g. `[email-smtp.ap-southeast-1.amazonaws.com]:587`, empty =
send direct), `RELAY_USER`, `RELAY_PASS`, `TLS_MODE` (`acme` | `internal` for
tests), `MESSAGE_SIZE_MB` (25), `SRS_SECRET` (auto-generated into a volume if
empty), `TZ`.

## mail container

Entrypoint (plain sh, no supervisor daemon): render config from env, wait for
`/db/mail.db`, pick TLS cert (Caddy's cert for `MAIL_HOST` from `caddy_data`
if present, else generate self-signed), start postsrsd, dovecot, postfix; a
background loop re-checks the cert hourly and reloads on change; container
exits if postfix or dovecot dies (compose `restart: unless-stopped`). Logs to
stdout.

Postfix:
- `virtual_mailbox_domains = proxy:sqlite:` → `SELECT 1 FROM domains WHERE name='%s'`
- `virtual_mailbox_maps` → `SELECT 1 FROM accounts WHERE email='%s' AND active=1`
- `virtual_alias_maps` → `SELECT destination FROM v_forward WHERE address='%s'`
- `smtpd_sender_login_maps` → `SELECT login FROM v_sender WHERE address='%s'`
- `virtual_transport = lmtp:unix:private/dovecot-lmtp`
- Port 25: no auth offered; `reject_unauth_destination`, unknown recipients
  rejected at RCPT, `reject_non_fqdn_*`, pipelining/helo sanity. Not an open relay.
- 587 (STARTTLS required) and 465 (implicit TLS): SASL via Dovecot socket,
  `reject_authenticated_sender_login_mismatch`, `permit_sasl_authenticated, reject`.
- rspamd milter `inet:rspamd:11332` on all smtpd, `milter_default_action = accept`.
- TLS ≥ 1.2, `smtp_tls_security_level = may` outbound.
- Forwarding: postsrsd (`sender_canonical_maps`/`recipient_canonical_maps`
  tcp lookups, classes limited to envelope), SRS domain = `PRIMARY_DOMAIN`.
- Relay, only when `RELAYHOST` set: `sender_dependent_relayhost_maps = pcre:`
  ```
  if !/^SRS[01][=+-]/
  /@/    ${RELAYHOST}
  endif
  ```
  plus `smtp_sasl_*` for the relay. Result: mail authored by our users goes
  via the relay; SRS-rewritten forwards and bounces go direct (relays reject
  foreign From addresses). Leave global `relayhost` empty.
- `message_size_limit` from env; sane queue lifetimes; `smtpd_client_*_rate_limit`.

Dovecot 2.3:
- `passdb sql` (sqlite): `SELECT email AS user, password FROM accounts WHERE email='%u' AND active=1`
- `userdb sql`: `SELECT '/var/mail/%d/%n' AS home, 5000 AS uid, 5000 AS gid, '*:storage=' || quota_mb || 'M' AS quota_rule FROM accounts WHERE email='%u' AND active=1`; plus `iterate_query`.
- Maildir under home, user `vmail` 5000:5000, `auth_cache_size` on (bcrypt is
  slow by design), `auth_mechanisms = plain login`, TLS only (`ssl = required`).
- LMTP + quota plugin (reject over-quota at LMTP with a clear message),
  sieve with a global `before` script filing `X-Spam: Yes` into `Junk`,
  auto-created Sent/Drafts/Junk/Trash with special-use flags, Trash/Junk
  autoexpunge 30d.
- IMAPS 993 only. Lowercase usernames (`auth_username_format = %Lu`).

## rspamd
`local.d` only: `worker-proxy.inc` (milter, self-scan), `redis.conf`,
`dkim_signing.conf` (`path = "/dkim/$domain.$selector.key"`, selector `mail`,
sign authenticated mail, `allow_username_mismatch = true`),
`milter_headers.conf` (add `X-Spam`, `Authentication-Results`),
`ratelimit.conf` (per authenticated user, default 200 rcpt/hour),
`actions.conf` (reject 15, add header 6, greylist 4), bayes autolearn on.
Controller not exposed publicly.

## admin app (`admin/`)

Go 1.24, stdlib `net/http` + `html/template` + `embed`, deps limited to
`modernc.org/sqlite` (pure Go, no cgo) and `golang.org/x/crypto/bcrypt`.
Server-rendered HTML, one small embedded CSS file, **no JS framework, no
build step**. Single static binary `rokmail`.

Subcommands: `serve` (default), `admin-create -email -password`,
`import <file.csv>`, `backup-db <dest>` (`VACUUM INTO`), `passwd -email`.

Env: `DB_PATH` (/db/mail.db), `DKIM_DIR` (/dkim), `LISTEN` (:8080),
`MAIL_HOST`, `PRIMARY_DOMAIN`, `ADMIN_EMAIL`/`ADMIN_PASSWORD`,
`SESSION_HOURS` (12), `ALLOW_USER_FORWARD` (false), `DEFAULT_QUOTA_MB` (1024).

On start: apply `schema.sql`, set WAL + `busy_timeout`, ensure
`PRIMARY_DOMAIN` exists, bootstrap superadmin if none, ensure DKIM key per
domain (RSA 2048, PEM at `$DKIM_DIR/<domain>.mail.key`, mode 0644).

### Roles (accounts.role) — keep the whole matrix in one file `rbac.go`

| Capability | superadmin | admin | helpdesk | user |
|---|---|---|---|---|
| Domains, departments, DNS page, audit log | ✔ | – | – | – |
| Change an account's role / department | ✔ | – | – | – |
| Create / edit / delete accounts | all | own department, role `user` only | – | – |
| Create / edit / delete aliases + members | all | own department | – | – |
| List accounts & aliases | all | own department | own department | – |
| Reset password, enable/disable | all | own dept, target role `user`/`helpdesk` | own dept, target role `user` | – |
| CSV import / export | ✔ | – | – | – |
| Change own password; own forwarding if `ALLOW_USER_FORWARD` | ✔ | ✔ | ✔ | ✔ |

An `admin`/`helpdesk` with no department sees nothing. Nobody can modify or
demote an account of equal or higher rank except superadmin; the last active
superadmin cannot be deleted, disabled or demoted. Enforce on the server for
every handler (not just by hiding links).

### Pages
Login · Dashboard (counts) · Accounts (search, filter by department/status,
paginate 50) · Account form · Aliases · Alias form with members (+ per-member
"may send as") · Departments · Domains · **DNS** (exact MX, SPF, DKIM public
key, DMARC, PTR records to publish per domain) · Audit log · My account.

### Rules
- Lowercase + validate every address; account/alias domain must exist in
  `domains`; alias address must not collide with an account email and vice versa.
- Passwords: min 10 chars, bcrypt cost 10, stored as `{BLF-CRYPT}$2a$…`.
  "Generate" option shows the random password once.
- Sessions: 32-byte random cookie token, sha256 stored; `HttpOnly`, `Secure`
  (unless `INSECURE_COOKIES=1` for local tests), `SameSite=Strict`. CSRF token
  on every POST. Password change / disable kills that account's sessions.
- Login throttle: in-memory, 5 failures per 15 min per (IP, email); constant
  work on unknown users. Trust `X-Forwarded-For` only from the proxy.
- Security headers (CSP `default-src 'self'`, `X-Frame-Options: DENY`, …).
- Every mutation writes `audit_log`.
- `GET /healthz` unauthenticated.
- CSV import columns: `email,name,type,department,quota_mb,forward_to,members,role`
  (`type` = `mailbox` | `alias`; `members` = `;`-separated, suffix `:send`
  grants send-as). Idempotent upsert, creates missing departments, validates
  the whole file before writing (single transaction), reports per-line errors.
  New mailboxes get random passwords returned once as a credentials CSV.

### Tests (`go test ./...` must pass)
RBAC matrix (table-driven, every role × capability × own/other department);
schema views (`v_forward`, `v_sender` for forwarding with/without copy,
inactive account/alias, send-as member); handlers via `httptest` (login,
CSRF rejection, a department admin cannot touch another department,
last-superadmin guard); CSV import (valid, invalid → nothing written).

## scripts
- `scripts/backup.sh`: `rokmail backup-db`, then restic (env-configured S3
  repo) of db dump + maildata + dkim + `.env`; prune 7 daily / 4 weekly.
- `scripts/smoke.sh`: brings the stack up with `TLS_MODE=internal`, creates
  two accounts + one alias through the CLI/DB, then verifies: local delivery
  via port 25 arrives over IMAPS; alias fan-out; unknown recipient rejected;
  relay attempt without auth rejected; authenticated submit on 587 works;
  sending as someone else's address is rejected; send-as-alias works for a
  permitted member.

## docs/SETUP.md
VPS requirements (port 25 inbound, PTR), install steps, DNS records, relay
(SES) setup, creating users / CSV import, Zoho migration with imapsync,
client settings (IMAP 993 / SMTP 587), backup + restore, upgrade, and a short
troubleshooting section (queue, logs).
