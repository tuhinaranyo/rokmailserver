#!/bin/sh
# Container entrypoint: render env-dependent config, pick the TLS cert, start
# postsrsd + dovecot + postfix, and exit as soon as any of them dies so that
# compose (restart: unless-stopped) restarts the whole container.
set -eu

: "${MAIL_HOST:?MAIL_HOST is required}"
: "${PRIMARY_DOMAIN:?PRIMARY_DOMAIN is required}"
RELAYHOST=${RELAYHOST:-}
RELAY_USER=${RELAY_USER:-}
RELAY_PASS=${RELAY_PASS:-}
MESSAGE_SIZE_MB=${MESSAGE_SIZE_MB:-25}
SRS_SECRET=${SRS_SECRET:-}

RUN=/run/rokmail
TLS=$RUN/tls
STATE=/var/lib/rokmail          # persistent volume (generated SRS secret)
CADDY=/caddy                    # caddy_data volume, read-only
DB=/db/mail.db

log() { echo "[rokmail] $*"; }

umask 077
mkdir -p "$TLS" "$STATE"

# ---------------------------------------------------------------- TLS cert
# Caddy keeps certs at caddy/certificates/<issuer-dir>/<host>/<host>.{crt,key} inside its
# data volume (the image sets XDG_DATA_HOME=/data, so the data dir is /data/caddy).
find_caddy_cert() {
  ls -t "$CADDY"/caddy/certificates/*/"$MAIL_HOST"/"$MAIL_HOST".crt 2>/dev/null | while read -r crt; do
    [ -s "$crt" ] && [ -s "${crt%.crt}.key" ] && { echo "$crt"; break; }
  done
}

# Installs the best available cert into $TLS. Returns 0 if it changed.
refresh_cert() {
  crt=$(find_caddy_cert)
  if [ -n "$crt" ]; then
    new_src="caddy:$crt"
    cp "$crt" "$TLS/new.crt"; cp "${crt%.crt}.key" "$TLS/new.key"
  else
    if [ ! -s "$TLS/self.crt" ]; then
      log "no Caddy certificate for $MAIL_HOST yet, generating a self-signed one"
      openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -subj "/CN=$MAIL_HOST" \
        -addext "subjectAltName=DNS:$MAIL_HOST" \
        -keyout "$TLS/self.key" -out "$TLS/self.crt" 2>/dev/null
    fi
    new_src="self-signed"
    cp "$TLS/self.crt" "$TLS/new.crt"; cp "$TLS/self.key" "$TLS/new.key"
  fi
  new_sum=$(cat "$TLS/new.crt" "$TLS/new.key" | cksum)
  if [ -s "$TLS/fullchain.pem" ] && [ "$new_sum" = "$(cat "$TLS/current.sum" 2>/dev/null)" ]; then
    rm -f "$TLS/new.crt" "$TLS/new.key"
    return 1
  fi
  mv "$TLS/new.key" "$TLS/privkey.pem"; mv "$TLS/new.crt" "$TLS/fullchain.pem"
  echo "$new_sum" > "$TLS/current.sum"
  echo "$new_src" > "$TLS/source"
  log "TLS certificate in use: $new_src"
}

# ---------------------------------------------------------------- SRS secret
if [ -n "$SRS_SECRET" ]; then
  printf '%s' "$SRS_SECRET" > "$RUN/srs.secret"
else
  [ -s "$STATE/srs.secret" ] || head -c 32 /dev/urandom | base64 > "$STATE/srs.secret"
  cp "$STATE/srs.secret" "$RUN/srs.secret"
fi

# ---------------------------------------------------------------- Postfix config
postconf -e \
  "myhostname = $MAIL_HOST" \
  "myorigin = $PRIMARY_DOMAIN" \
  "message_size_limit = $((MESSAGE_SIZE_MB * 1048576))"

if [ -n "$RELAYHOST" ]; then
  log "outbound relay for our users' mail: $RELAYHOST"
  # Mail authored by our users goes through the relay; SRS-rewritten forwards
  # and bounces go direct (relays reject foreign From addresses).
  cat > /etc/postfix/relay_by_sender.pcre <<PCRE
if !/^SRS[01][=+-]/
/@/    $RELAYHOST
endif
PCRE
  printf '%s encrypt\n' "$RELAYHOST" > /etc/postfix/relay_tls_policy
  printf '%s %s:%s\n' "$RELAYHOST" "$RELAY_USER" "$RELAY_PASS" > /etc/postfix/relay_sasl_passwd
  postmap hash:/etc/postfix/relay_tls_policy hash:/etc/postfix/relay_sasl_passwd
  postconf -e \
    "sender_dependent_relayhost_maps = pcre:/etc/postfix/relay_by_sender.pcre" \
    "smtp_sasl_auth_enable = yes" \
    "smtp_sasl_password_maps = hash:/etc/postfix/relay_sasl_passwd" \
    "smtp_sasl_security_options = noanonymous" \
    "smtp_tls_policy_maps = hash:/etc/postfix/relay_tls_policy"
else
  log "no RELAYHOST set: delivering directly to recipient MX hosts"
  postconf -X sender_dependent_relayhost_maps smtp_sasl_auth_enable \
    smtp_sasl_password_maps smtp_sasl_security_options smtp_tls_policy_maps
fi

cat > "$RUN/dovecot-env.conf" <<DOVECOT
hostname = $MAIL_HOST
postmaster_address = postmaster@$PRIMARY_DOMAIN
DOVECOT

# ---------------------------------------------------------------- wait for the DB
# The admin app creates /db/mail.db. After that, mail flow does not need admin.
n=0
until [ -s "$DB" ] && [ "$(sqlite3 "$DB" "SELECT count(*) FROM sqlite_master WHERE name IN ('domains','accounts','v_forward','v_sender')" 2>/dev/null)" = 4 ]; do
  [ $((n % 15)) -eq 0 ] && log "waiting for $DB (created by the admin container)..."
  n=$((n + 1)); sleep 2
done

refresh_cert || true
postfix check
doveconf -n >/dev/null   # fail early with a readable error on a config mistake

# ---------------------------------------------------------------- start
postsrsd -f 10001 -r 10002 -d "$PRIMARY_DOMAIN" -s "$RUN/srs.secret" -a = \
  -u postsrsd -c /var/lib/postsrsd -l 127.0.0.1 &
SRS=$!
dovecot -F &
DC=$!
# Dovecot creates its sockets inside Postfix's queue directory.
n=0; until [ -S /var/spool/postfix/private/auth ] && [ -S /var/spool/postfix/private/dovecot-lmtp ]; do
  kill -0 "$DC" 2>/dev/null || { log "dovecot failed to start"; exit 1; }
  n=$((n + 1)); [ "$n" -gt 60 ] && { log "dovecot sockets did not appear"; exit 1; }
  sleep 1
done
postfix start-fg &
PF=$!

# Re-check the cert: every minute until Caddy has issued one, then hourly.
(
  while :; do
    if [ "$(cat "$TLS/source" 2>/dev/null)" = "self-signed" ]; then sleep 60; else sleep 3600; fi
    if refresh_cert; then
      log "certificate changed, reloading postfix and dovecot"
      postfix reload || true
      doveadm reload || true
    fi
  done
) &
LOOP=$!

stop() {
  trap - TERM INT
  kill "$LOOP" 2>/dev/null || true
  kill -TERM "$PF" "$DC" "$SRS" 2>/dev/null || true
  wait 2>/dev/null || true
  exit "${1:-0}"
}
trap 'stop 0' TERM INT

while kill -0 "$PF" 2>/dev/null && kill -0 "$DC" 2>/dev/null && kill -0 "$SRS" 2>/dev/null; do
  sleep 2
done
log "postfix, dovecot or postsrsd exited; stopping the container so it gets restarted"
stop 1
