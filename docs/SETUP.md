# rokmail setup and operations

Everything runs from `deploy/` with Docker Compose. Replace `rokomari.com` and
`mail.rokomari.com` with your own names (`PRIMARY_DOMAIN`, `MAIL_HOST` in `.env`).

## 1. Server requirements

- A VPS with 2-4 vCPU, 2 GB RAM (the stack idles well under 400 MB), 20 GB+ disk for mail, Docker with the compose plugin.
- A **static public IPv4**. IPv6 is not used.
- **Inbound** TCP 25, 465, 587, 993, 80, 443 open (firewall and provider).
- **Outbound** TCP 25 open if you send directly. Many providers block it by default;
  if yours does, use a relay (section 5), which only needs outbound 587.
- A **PTR (reverse DNS)** record for the IP pointing to `MAIL_HOST`
  (`mail.rokomari.com`), set in the provider's panel. Receivers check it. It is not optional for direct sending.
- DNS you can edit for the mail domain.

## 2. Install

```sh
git clone <repo> /opt/rokmail && cd /opt/rokmail/deploy
cp .env.example .env
$EDITOR .env           # MAIL_HOST, PRIMARY_DOMAIN, ADMIN_EMAIL, ADMIN_PASSWORD, RELAYHOST...
chmod 600 .env
docker compose up -d --build
docker compose ps
```

First start:

- The `admin` container creates the database, the superadmin from `ADMIN_EMAIL` / `ADMIN_PASSWORD`, the primary domain and a DKIM key.
  The password is only used while no superadmin exists; change it in the panel afterwards.
- `caddy` requests a Let's Encrypt certificate for `MAIL_HOST` (needs the A record from section 3 and ports 80/443 reachable).
  Until it exists, the `mail` container serves a self-signed certificate, checks every minute and switches (reloading Postfix
  and Dovecot) as soon as Caddy has one. After that it re-checks hourly, so renewals are picked up automatically.
  Check with `docker compose exec mail cat /run/rokmail/tls/source` (`caddy:...` or `self-signed`).
- The admin panel is at `https://MAIL_HOST/`.
- Optional webmail (Roundcube) at `https://MAIL_HOST/webmail/`: `docker compose --profile webmail up -d`.

Test without public DNS: set `TLS_MODE=internal` (Caddy uses its own CA, mail clients will warn). `scripts/smoke.sh` does this for you
in a separate compose project and tears it down afterwards.

## 3. DNS records

The panel page **DNS** (superadmin) lists the exact records for every domain, including the DKIM public key. The set is:

| Name | Type | Value |
|---|---|---|
| `mail.rokomari.com` | A | the server IP |
| `rokomari.com` | MX | `10 mail.rokomari.com.` |
| `rokomari.com` | TXT (SPF) | `v=spf1 mx ~all` (with SES: `v=spf1 mx include:amazonses.com ~all`) |
| `mail._domainkey.rokomari.com` | TXT | `v=DKIM1; k=rsa; p=...` (from the DNS page) |
| `_dmarc.rokomari.com` | TXT | `v=DMARC1; p=none; rua=mailto:postmaster@rokomari.com` |
| PTR of the server IP | PTR | `mail.rokomari.com` (at the VPS provider) |

Start DMARC at `p=none`, watch the reports for a couple of weeks, then move to `quarantine`.
Create a `postmaster@` alias (Aliases page) so DMARC reports and bounce notices have somewhere to go.
Every additional domain needs its own MX, SPF, DKIM and DMARC records. Add it under Domains first.

## 4. Users and aliases

- In the panel: Departments, then Accounts and Aliases. Passwords are at least 10 characters; "Generate" shows one once.
- From the command line (the admin image is minimal, so use `run`):

```sh
docker compose run --rm admin admin-create -email boss@rokomari.com -password 'a-long-password'
docker compose run --rm admin passwd -email someone@rokomari.com          # prints a generated password
```

- CSV import (columns `email,name,type,department,quota_mb,forward_to,members,role`; `type` is `mailbox` or `alias`,
  `members` is `;`-separated, suffix `:send` allows send-as). The whole file is validated first; nothing is written if any line is invalid.
  New mailbox passwords are printed once as CSV on stdout:

```sh
docker compose run --rm -v "$PWD/users.csv:/import.csv:ro" admin import /import.csv > credentials.csv
chmod 600 credentials.csv     # hand out, then delete
```

A disabled account or a changed forward takes effect at once for new mail. Dovecot caches logins for up to 5 minutes,
so a disabled mailbox can keep an already-cached login for that long.

## 5. Outbound relay (Amazon SES)

Sending directly from a VPS IP often lands in spam and port 25 may be blocked. A relay fixes both.

1. In SES (your region), verify the domain `rokomari.com`, and request production access (leave the sandbox).
2. Create SMTP credentials (SES console, SMTP settings). These are not your AWS keys.
3. In `.env`:

```
RELAYHOST=[email-smtp.ap-southeast-1.amazonaws.com]:587
RELAY_USER=<SES SMTP username>
RELAY_PASS=<SES SMTP password>
```

4. `docker compose up -d mail`. Use the SPF form with `include:amazonses.com`.

How it routes: mail written by your users goes through the relay; forwarded mail (rewritten with SRS) and bounces go out directly,
because relays reject senders they do not own. Relay connections require TLS (use a `:587` STARTTLS endpoint).
Empty `RELAYHOST` sends everything directly.

## 6. Mail client settings

| | |
|---|---|
| Username | full address, e.g. `alice@rokomari.com` |
| Incoming (IMAP) | `mail.rokomari.com`, port **993**, SSL/TLS |
| Outgoing (SMTP) | `mail.rokomari.com`, port **587**, STARTTLS (or **465**, SSL/TLS), authentication required |

There is no POP3 and no plain IMAP/143. Special folders (Sent, Drafts, Junk, Trash) are created automatically;
Junk and Trash are emptied after 30 days. Spam above the "add header" score is filed into Junk.

## 7. Migrating from Zoho with imapsync

1. Create all accounts first (CSV import) and note each new password.
2. Lower the MX TTL a day ahead. For each user you need the Zoho password or an app-specific password
   (Zoho: Security, App passwords; IMAP access must be enabled). Use your Zoho IMAP host
   (`imap.zoho.com`, or `imap.zoho.eu`, `imap.zoho.in`, ... depending on the data centre).
3. Build `users.txt`, one line per user: `zoho_user;zoho_password;new_user;new_password`.
4. Run a first pass while Zoho is still live, then again right after switching the MX to catch the stragglers:

```sh
while IFS=';' read -r u1 p1 u2 p2; do
  docker run --rm gilleslamiral/imapsync imapsync \
    --host1 imap.zoho.com --ssl1 --user1 "$u1" --password1 "$p1" \
    --host2 mail.rokomari.com --ssl2 --user2 "$u2" --password2 "$p2" \
    --automap --addheader
done < users.txt
```

`imapsync` is safe to repeat; it only copies what is missing. Role addresses on Zoho (groups, shared mailboxes) become aliases
(CSV `type=alias`). Remember to move SPF, DKIM and DMARC at the same time as the MX, and to tell users the new client settings.

## 8. Backup and restore

`scripts/backup.sh` dumps the database (`rokmail backup-db`, a consistent copy even with live traffic) and uploads the dump, mailboxes,
DKIM keys, the SRS secret and `.env` with restic (run from its own Docker image), then keeps 7 daily and 4 weekly snapshots.

Add to `.env`: `RESTIC_REPOSITORY` (for example `s3:https://s3.ap-southeast-1.amazonaws.com/bucket/rokmail`), `RESTIC_PASSWORD`,
`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`. Keep the restic password somewhere other than this server. Then:

```sh
sudo crontab -e
15 3 * * *  /opt/rokmail/scripts/backup.sh >> /var/log/rokmail-backup.log 2>&1
```

Restore onto a fresh server (same repo settings in your shell or `.env`):

```sh
cd /opt/rokmail/deploy && docker compose down
P=rokmail   # compose project name
docker run --rm -e RESTIC_REPOSITORY -e RESTIC_PASSWORD -e AWS_ACCESS_KEY_ID -e AWS_SECRET_ACCESS_KEY \
  -v ${P}_db:/data/db -v ${P}_maildata:/data/maildata -v ${P}_dkim:/data/dkim -v ${P}_mail_state:/data/mail_state \
  -v "$PWD/restore:/data/env" restic/restic:0.18.0 restore latest --target /
# put the dump in place; the admin app recreates -wal/-shm
docker run --rm --entrypoint sh -v ${P}_db:/data/db restic/restic:0.18.0 -c \
  'rm -f /data/db/mail.db*; cp "$(ls -1t /data/db/backups/mail-*.db | head -1)" /data/db/mail.db; chmod 0777 /data/db; chmod 0666 /data/db/mail.db'
cp restore/.env .env     # the restored copy of the old .env
docker compose up -d
```

Test a restore occasionally. Messages delivered after the last backup are not in it; Dovecot's maildirs are plain files
and can be copied live.

## 9. Upgrade

```sh
cd /opt/rokmail && git pull
cd deploy && docker compose up -d --build     # rebuilds mail and admin, pulls pinned images if their tags changed
docker image prune -f
```

The admin app applies schema changes (idempotent) on start. Mail keeps flowing while `admin` restarts, and a short
restart of `mail` only delays inbound mail (senders retry). Image tags are pinned in `docker-compose.yml`; change them deliberately.

## 10. Troubleshooting

```sh
docker compose ps                              # health of every service
docker compose logs -f mail                    # Postfix + Dovecot + postsrsd, one stream
docker compose logs --tail 100 rspamd caddy
docker compose exec mail postqueue -p          # the queue
docker compose exec mail postqueue -f          # retry everything now
docker compose exec mail postcat -q QUEUEID    # look at one queued message
docker compose exec mail doveadm user '*'      # does Dovecot see the accounts?
docker compose exec mail doveadm auth test alice@rokomari.com   # test a login
docker compose exec mail sqlite3 /db/mail.db "select * from v_forward"
docker compose exec mail postmap -q alice@rokomari.com sqlite:/etc/postfix/sql/mailboxes.cf
```

- **Cannot log in over IMAP/SMTP:** use the full address as username; check `doveadm auth test`; the account must be active.
- **"Relay access denied" when sending:** the client is not authenticated or is using port 25. Use 587 or 465.
- **"Sender address rejected: not owned by user":** the From/envelope address is not yours. For a role address the account must be a member with "may send as".
- **Mail to you is rejected "User unknown":** the account or alias does not exist or is disabled, or the domain is missing under Domains.
- **Outbound mail deferred:** `postqueue -p` and the log line show the reason (port 25 blocked, relay credentials, blocklisted IP).
- **Certificate warnings:** `docker compose exec mail cat /run/rokmail/tls/source`; if `self-signed`, check `docker compose logs caddy` and DNS/ports 80 and 443.
- **Mail container restarts in a loop:** `docker compose logs mail`. It exits on purpose when Postfix, Dovecot or postsrsd dies,
  and it waits (logging) for `/db/mail.db`, which the admin container creates on its first start.
- **Mail works with admin stopped:** yes, by design; only the panel and DKIM key creation need `admin`.
- **Memory:** `docker stats --no-stream`. Limits are set in `docker-compose.yml`.
