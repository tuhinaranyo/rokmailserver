#!/bin/sh
# End-to-end smoke test. Brings the stack up under its own compose project
# (rokmail-smoke, TLS_MODE=internal, ports remapped to 127.0.0.1:12xxx), creates
# test accounts straight in the SQLite DB, stops the admin container, then checks
# delivery, aliases, auth rules, SRS and relay routing. Needs: docker compose, python3.
#
#   scripts/smoke.sh            run, then tear everything down
#   KEEP=1 scripts/smoke.sh     leave the stack running afterwards
set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"
PROJECT=rokmail-smoke
WORK=$(mktemp -d)
BASE=${SMOKE_PORT_BASE:-12000}
P_SMTP=$((BASE + 25)); P_SUB=$((BASE + 587)); P_SMTPS=$((BASE + 465)); P_IMAPS=$((BASE + 993))
HOST=mail.smoke.test
DOMAIN=smoke.test
PASSWORD='Smoke-test-pw-1'

dc() { docker compose -p "$PROJECT" --env-file "$WORK/env" \
         -f deploy/docker-compose.yml -f "$WORK/override.yml" "$@"; }
say() { printf '\n== %s\n' "$*"; }
cleanup() {
  if [ "${KEEP:-0}" = 1 ]; then echo "KEEP=1: stack left running (project $PROJECT, files in $WORK)"; return; fi
  dc down -v --remove-orphans >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

write_env() { # $1 = RELAYHOST
  cat > "$WORK/env" <<EOF
MAIL_HOST=$HOST
PRIMARY_DOMAIN=$DOMAIN
ADMIN_EMAIL=admin@$DOMAIN
ADMIN_PASSWORD=Admin-smoke-pw-12
TLS_MODE=internal
RELAYHOST=$1
RELAY_USER=relayuser
RELAY_PASS=relaypass
MESSAGE_SIZE_MB=25
TZ=UTC
EOF
}
write_env ""
cat > "$WORK/override.yml" <<EOF
services:
  mail:
    ports: !override
      - "127.0.0.1:$P_SMTP:25"
      - "127.0.0.1:$P_SMTPS:465"
      - "127.0.0.1:$P_SUB:587"
      - "127.0.0.1:$P_IMAPS:993"
  caddy:
    ports: !override
      - "127.0.0.1:$((BASE + 80)):80"
      - "127.0.0.1:$((BASE + 443)):443"
EOF

wait_healthy() { # service, seconds
  i=0
  while [ $i -lt "$2" ]; do
    cid=$(dc ps -q "$1" 2>/dev/null || true)
    [ -n "$cid" ] && [ "$(docker inspect -f '{{.State.Health.Status}}' "$cid" 2>/dev/null)" = healthy ] && return 0
    i=$((i + 2)); sleep 2
  done
  echo "FAIL: $1 not healthy after $2s"; dc logs --tail 40 "$1" || true; return 1
}

# ------------------------------------------------------------------ start
say "building and starting the stack"
dc down -v --remove-orphans >/dev/null 2>&1 || true
WITH_ADMIN=0
# SMOKE_NO_BUILD=1 reuses already-built rokmail-mail:1 / rokmail-admin:1 images.
BUILD=--build; [ "${SMOKE_NO_BUILD:-0}" = 1 ] && BUILD=--no-build
if [ -f admin/Dockerfile ] && { [ "${SMOKE_NO_BUILD:-0}" = 1 ] || dc build admin; }; then WITH_ADMIN=1; fi
if [ $WITH_ADMIN = 1 ]; then
  dc up -d $BUILD
else
  echo "NOTE: admin image not available; creating the DB from admin/schema.sql instead"
  dc up -d $BUILD mail rspamd redis caddy
fi

if [ $WITH_ADMIN = 1 ]; then
  i=0; until dc exec -T mail test -s /db/mail.db 2>/dev/null; do
    i=$((i + 1)); [ $i -gt 60 ] && { echo "FAIL: admin never created /db/mail.db"; dc logs admin; exit 1; }; sleep 2
  done
else
  # same permissions the admin app would use (dir 0777, files 0666)
  dc exec -T mail sh -c 'umask 0; chmod 0777 /db; sqlite3 /db/mail.db "PRAGMA journal_mode=WAL;" >/dev/null; sqlite3 /db/mail.db' < admin/schema.sql
  dc exec -T mail sh -c 'chmod 0666 /db/mail.db*'
fi

say "creating test accounts and one alias in the database"
HASH=$(dc exec -T mail doveadm pw -s BLF-CRYPT -p "$PASSWORD" | tr -d '\r\n')
dc exec -T mail sqlite3 /db/mail.db <<SQL
.timeout 5000
INSERT OR IGNORE INTO domains(name) VALUES ('$DOMAIN');
INSERT INTO accounts(email,name,password) VALUES ('alice@$DOMAIN','Alice','$HASH')
  ON CONFLICT(email) DO UPDATE SET password=excluded.password;
INSERT INTO accounts(email,name,password) VALUES ('bob@$DOMAIN','Bob','$HASH')
  ON CONFLICT(email) DO UPDATE SET password=excluded.password;
INSERT INTO accounts(email,name,password,forward_to,keep_copy) VALUES ('carol@$DOMAIN','Carol','$HASH','fwd@example.net',1)
  ON CONFLICT(email) DO UPDATE SET password=excluded.password;
INSERT INTO accounts(email,name,password,quota_mb) VALUES ('dave@$DOMAIN','Dave','$HASH',1)
  ON CONFLICT(email) DO UPDATE SET password=excluded.password;
INSERT OR IGNORE INTO aliases(address) VALUES ('support@$DOMAIN');
INSERT OR REPLACE INTO alias_members(alias_id,destination,can_send)
  SELECT id,'alice@$DOMAIN',0 FROM aliases WHERE address='support@$DOMAIN';
INSERT OR REPLACE INTO alias_members(alias_id,destination,can_send)
  SELECT id,'bob@$DOMAIN',1 FROM aliases WHERE address='support@$DOMAIN';
SQL
dc exec -T mail sh -c 'chmod 0666 /db/mail.db*'

wait_healthy mail 120
if [ $WITH_ADMIN = 1 ]; then
  say "stopping the admin container: mail must keep working without it"
  dc stop admin
fi

# ------------------------------------------------------------------ cert
say "waiting for the mail container to pick up Caddy's internal certificate"
i=0; until [ "$(dc exec -T mail cat /run/rokmail/tls/source 2>/dev/null | cut -c1-6)" = caddy: ]; do
  i=$((i + 1)); [ $i -gt 50 ] && { echo "FAIL: still using the self-signed certificate"; dc logs --tail 30 caddy; exit 1; }; sleep 3
done
dc exec -T mail cat /run/rokmail/tls/source
sleep 2

# ------------------------------------------------------------------ protocol tests
say "SMTP / IMAP checks"
cat > "$WORK/smoke_client.py" <<'PY'
import imaplib, smtplib, ssl, sys, time, uuid, email.message, email.utils, subprocess

host, p25, p587, p465, p993, domain, pw = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4]), int(sys.argv[5]), sys.argv[6], sys.argv[7]
dc_logs = sys.argv[8:]          # command that prints the mail container log
ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
A, B, C, D, SUP = (f"{n}@{domain}" for n in ("alice", "bob", "carol", "dave", "support"))
fails = []

def check(name, ok, detail=""):
    print(("PASS  " if ok else "FAIL  ") + name + ("" if ok or not detail else "  -> " + str(detail)))
    if not ok: fails.append(name)

def msg(frm, to, tag, extra=None):
    m = email.message.EmailMessage()
    m["From"], m["To"], m["Subject"] = frm, to, tag
    m["Date"] = email.utils.formatdate(localtime=False); m["Message-ID"] = f"<{uuid.uuid4()}@client.example.org>"
    for k, v in (extra or {}).items(): m[k] = v
    m.set_content("smoke test body " + tag)
    return m.as_string()

def tag(): return "smoke-" + uuid.uuid4().hex[:10]

def inbox_has(user, subject, folder="INBOX", wait=25):
    end = time.time() + wait
    while time.time() < end:
        try:
            im = imaplib.IMAP4_SSL(host, p993, ssl_context=ctx)
            im.login(user, pw); im.select(folder, readonly=True)
            typ, data = im.search(None, "SUBJECT", f'"{subject}"'); im.logout()
            if data and data[0]: return True
        except Exception as e:
            last = e
        time.sleep(1.5)
    return False

def smtp25():
    s = smtplib.SMTP(host, p25, timeout=30); s.ehlo("client.example.org"); return s

def submit(port, login, frm, to, subject, ssl_wrap=False, extra=None):
    s = smtplib.SMTP_SSL(host, port, context=ctx, timeout=30) if ssl_wrap else smtplib.SMTP(host, port, timeout=30)
    s.ehlo("client.example.org")
    if not ssl_wrap: s.starttls(context=ctx); s.ehlo("client.example.org")
    s.login(login, pw)
    try:
        return s.sendmail(frm, [to], msg(frm, to, subject, extra))
    finally:
        try: s.quit()
        except Exception: pass

# --- port 25 behaviour
s = smtp25()
check("25: no AUTH advertised before STARTTLS", "auth" not in s.esmtp_features)
check("25: STARTTLS offered", s.has_extn("starttls"))
s.starttls(context=ctx); s.ehlo("client.example.org")
check("25: no AUTH advertised after STARTTLS", "auth" not in s.esmtp_features, s.esmtp_features)
code, resp = s.docmd("AUTH PLAIN AGFsaWNlQHNtb2tlLnRlc3QAeA==")
check("25: AUTH attempt refused", code >= 500, (code, resp))
s.quit()

s = smtp25(); s.mail("ext@external.example")
code, resp = s.rcpt("victim@example.org")
check("25: relay to a foreign domain without auth is rejected", code == 554 and b"elay" in resp, (code, resp))
code, resp = s.rcpt("nobody@" + domain)
check("25: unknown local recipient rejected at RCPT", code == 550, (code, resp))
code, resp = s.rcpt("bad-address")
check("25: non-FQDN recipient rejected", code >= 500, (code, resp))
s.quit()

# --- delivery
t = tag(); s = smtp25(); s.sendmail("ext@external.example", [A], msg("ext@external.example", A, t)); s.quit()
check("25: external -> alice delivered, visible over IMAPS", inbox_has(A, t))

t = tag(); s = smtp25(); s.sendmail("ext@external.example", [SUP], msg("ext@external.example", SUP, t)); s.quit()
check("alias fan-out: support@ reaches alice", inbox_has(A, t))
check("alias fan-out: support@ reaches bob", inbox_has(B, t))

t = tag(); s = smtp25(); s.sendmail("ext@external.example", [C], msg("ext@external.example", C, t)); s.quit()
check("forward with keep_copy: carol keeps a copy", inbox_has(C, t))

# --- submission
s = smtplib.SMTP(host, p587, timeout=30); s.ehlo("client.example.org")
check("587: AUTH not offered before STARTTLS", "auth" not in s.esmtp_features)
code, resp = s.docmd("MAIL FROM:<alice@%s>" % domain)
check("587: MAIL before STARTTLS refused", code == 530, (code, resp))
s.quit()

s = smtplib.SMTP(host, p587, timeout=30); s.ehlo("client.example.org"); s.starttls(context=ctx); s.ehlo("client.example.org")
check("587: AUTH offered after STARTTLS", "auth" in s.esmtp_features)
s.mail("alice@" + domain)
code, resp = s.rcpt(B)
check("587: unauthenticated submission refused", code >= 500, (code, resp))
s.quit()

try:
    s = smtplib.SMTP(host, p587, timeout=30); s.ehlo("client.example.org"); s.starttls(context=ctx); s.ehlo("client.example.org")
    s.login(A, "wrong-password"); check("587: wrong password rejected", False)
except smtplib.SMTPAuthenticationError:
    check("587: wrong password rejected", True)

t = tag(); submit(p587, A, A, B, t)
check("587: authenticated alice -> bob delivered", inbox_has(B, t))
t = tag(); submit(p465, B, B, A, t, ssl_wrap=True)
check("465: implicit TLS, authenticated bob -> alice delivered", inbox_has(A, t))

for port, label in ((p587, "587"), (p465, "465")):
    try:
        submit(port, A, B, A, tag(), ssl_wrap=(port == p465)); check(f"{label}: alice sending as bob rejected", False)
    except smtplib.SMTPSenderRefused as e:
        check(f"{label}: alice sending as bob rejected", e.smtp_code == 553, e)

try:
    submit(p587, A, SUP, B, tag()); check("587: alice (no send-as) sending as support@ rejected", False)
except smtplib.SMTPSenderRefused as e:
    check("587: alice (no send-as) sending as support@ rejected", e.smtp_code == 553, e)

t = tag(); submit(p587, B, SUP, A, t)
check("587: bob (send-as member) sending as support@ accepted and delivered", inbox_has(A, t))

# --- sieve / quota
t = tag(); s = smtp25()
s.sendmail("ext@external.example", [A], msg("ext@external.example", A, t, {"X-Spam": "Yes"})); s.quit()
check("forged X-Spam header from outside is ignored (stays in INBOX)", inbox_has(A, t))

# --- SRS / outbound sender rewriting, from the Postfix log
def mail_log():
    return subprocess.run(dc_logs, capture_output=True, text=True).stdout

t = tag(); s = smtp25(); s.sendmail("ext@sender.example", [C], msg("ext@sender.example", C, t)); s.quit()
t2 = tag(); submit(p587, A, A, "someone@example.net", t2)
time.sleep(8)
log = mail_log()
check("SRS: forwarded mail leaves with an SRS0= envelope sender",
      any("from=<SRS0=" in l and domain in l for l in log.splitlines()), "no from=<SRS0=...> in postfix log")
check("SRS: our own users' outbound mail is not SRS-rewritten",
      "from=<alice@%s>" % domain in log and "from=<SRS0=" in log and
      not any("from=<SRS0=" in l and "alice" in l for l in log.splitlines()))

print()
print("RESULT: %d failed" % len(fails) if fails else "RESULT: all protocol checks passed")
sys.exit(1 if fails else 0)
PY
python3 -I "$WORK/smoke_client.py" 127.0.0.1 "$P_SMTP" "$P_SUB" "$P_SMTPS" "$P_IMAPS" "$DOMAIN" "$PASSWORD" \
  docker compose -p "$PROJECT" --env-file "$WORK/env" -f deploy/docker-compose.yml -f "$WORK/override.yml" logs --no-log-prefix mail ||
  FAILED=1

# The client above connects to 127.0.0.1 but certificates are for $HOST; verification is
# intentionally off in the client (it checks protocol behaviour, not the PKI).

# ------------------------------------------------------------------ sieve, quota via LMTP
say "Junk filing (sieve) and over-quota rejection via LMTP"
lmtp() { # $1 recipient, stdin = message
  dc exec -T mail perl -MIO::Socket::UNIX -e '
    my ($rcpt)=@ARGV; local $/; my $body=<STDIN>; $body =~ s/\r?\n/\r\n/g;
    my $s=IO::Socket::UNIX->new("/var/spool/postfix/private/dovecot-lmtp") or die "connect: $!";
    my $rd=sub{ my $l; my $o=""; while(defined($l=<$s>)){ $o.=$l; last if $l=~/^\d{3} /; } print $o; };
    $rd->(); print $s "LHLO t\r\n"; $rd->(); print $s "MAIL FROM:<ext\@external.example>\r\n"; $rd->();
    print $s "RCPT TO:<$rcpt>\r\n"; $rd->(); print $s "DATA\r\n"; $rd->();
    print $s $body, "\r\n.\r\n"; $rd->(); print $s "QUIT\r\n";' "$1"
}
JTAG="junk-$$"
out=$(printf 'From: ext@external.example\nTo: alice@%s\nSubject: %s\nX-Spam: Yes\n\nspam\n' "$DOMAIN" "$JTAG" | lmtp "alice@$DOMAIN")
echo "$out" | tail -2
python3 -I - "$P_IMAPS" "alice@$DOMAIN" "$PASSWORD" "$JTAG" <<'PY' || FAILED=1
import imaplib, ssl, sys, time
port, user, pw, subj = int(sys.argv[1]), sys.argv[2], sys.argv[3], sys.argv[4]
ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
ok = False
for _ in range(10):
    im = imaplib.IMAP4_SSL("127.0.0.1", port, ssl_context=ctx); im.login(user, pw)
    folders = [l.decode() for l in im.list()[1]]
    im.select("Junk", readonly=True); typ, d = im.search(None, "SUBJECT", f'"{subj}"')
    ok = bool(d and d[0]); im.logout()
    if ok: break
    time.sleep(1)
print(("PASS  " if ok else "FAIL  ") + "X-Spam: Yes message filed into Junk by the global sieve script")
print(("PASS  " if any("\\Junk" in f and "\\Sent" not in f for f in folders) and any("\\Sent" in f for f in folders)
       and any("\\Drafts" in f for f in folders) and any("\\Trash" in f for f in folders) else "FAIL  ")
      + "special-use Junk/Sent/Drafts/Trash folders exist")
sys.exit(0 if ok else 1)
PY
out=$( { printf 'From: ext@external.example\nTo: dave@%s\nSubject: big\n\n' "$DOMAIN"; python3 -c 'import sys; sys.stdout.write(("x"*75+"\n")*20000)'; } | lmtp "dave@$DOMAIN")
echo "$out" | tail -2
case "$out" in
  *"552"*|*"452"*) echo "PASS  over-quota mail refused at LMTP: $(echo "$out" | tail -1 | tr -d '\r')" ;;
  *) echo "FAIL  over-quota mail was not refused"; FAILED=1 ;;
esac

# ------------------------------------------------------------------ container exits when postfix dies
say "container must exit (and be restarted) when Postfix dies"
cid=$(dc ps -q mail); before=$(docker inspect -f '{{.RestartCount}}' "$cid")
dc exec -T mail sh -c 'kill $(cat /var/spool/postfix/pid/master.pid)'
i=0; while [ "$(docker inspect -f '{{.RestartCount}}' "$cid")" = "$before" ] && [ $i -lt 30 ]; do i=$((i + 1)); sleep 2; done
if [ "$(docker inspect -f '{{.RestartCount}}' "$cid")" != "$before" ]; then
  echo "PASS  mail container restarted after postfix died"; wait_healthy mail 120 || FAILED=1
else
  echo "FAIL  mail container did not restart"; FAILED=1
fi

# ------------------------------------------------------------------ relay routing
say "RELAYHOST routing: users via relay, SRS forwards and bounces direct"
write_env "[127.0.0.1]:2525"          # nothing listens there; the log shows which path was chosen
dc up -d --no-build mail
wait_healthy mail 120
sleep 3
dc exec -T mail sendmail -f "alice@$DOMAIN" relaytest-user@example.net </dev/null >/dev/null 2>&1 || true
dc exec -T mail sh -c "printf 'Subject: x\n\nx\n' | sendmail -f ext@sender.example relaytest-fwd@example.net" || true
dc exec -T mail sh -c "printf 'Subject: x\n\nx\n' | sendmail -f '' relaytest-bounce@example.net" || true
dc exec -T mail sh -c "printf 'Subject: u\n\nx\n' | sendmail -f alice@$DOMAIN relaytest-user@example.net" || true
sleep 12
dc logs --no-log-prefix mail 2>&1 | grep -E 'relaytest-(user|fwd|bounce)@' | grep 'status=' | sed 's/^.*postfix\///' || true
RL=$(dc logs --no-log-prefix mail 2>&1)
route() { echo "$RL" | grep "to=<relaytest-$1@example.net>" | grep -E 'relay=|status=' | tail -1; }
case "$(route user)" in *"127.0.0.1[127.0.0.1]:2525"*) echo "PASS  user mail routed to RELAYHOST" ;; *) echo "FAIL  user mail not routed to RELAYHOST"; FAILED=1 ;; esac
case "$(route fwd)" in *"127.0.0.1"*) echo "FAIL  SRS-rewritten forward went to RELAYHOST"; FAILED=1 ;; *) echo "PASS  SRS-rewritten forward goes direct" ;; esac
case "$(route bounce)" in *"127.0.0.1"*) echo "FAIL  null-sender mail went to RELAYHOST"; FAILED=1 ;; *) echo "PASS  null-sender (bounce) mail goes direct" ;; esac

say "done"
if [ "${FAILED:-0}" = 1 ]; then echo "SMOKE TEST FAILED"; exit 1; fi
echo "SMOKE TEST PASSED"
