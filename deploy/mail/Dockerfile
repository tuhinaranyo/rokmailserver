# Postfix 3.8 + Dovecot 2.3. Stay on a base that ships Dovecot 2.3: 2.4 has a different config syntax.
# ubuntu:24.04 is the base the smoke test was run on; debian:bookworm-slim should also work (untested).
ARG BASE=ubuntu:24.04
FROM ${BASE}

ENV DEBIAN_FRONTEND=noninteractive
RUN echo "postfix postfix/main_mailer_type select No configuration" | debconf-set-selections \
 && apt-get update \
 && apt-get install -y --no-install-recommends \
      postfix postfix-sqlite postfix-pcre \
      dovecot-core dovecot-imapd dovecot-lmtpd dovecot-sieve dovecot-sqlite \
      postsrsd sqlite3 ca-certificates openssl \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd -g 5000 vmail \
 && useradd -u 5000 -g vmail -d /var/mail -s /usr/sbin/nologin vmail \
 && mkdir -p /var/mail /etc/dovecot/sieve /run/rokmail \
 && chown vmail:vmail /var/mail

COPY postfix/ /etc/postfix/
COPY dovecot/dovecot.conf dovecot/dovecot-sql.conf.ext /etc/dovecot/
COPY dovecot/before.sieve /etc/dovecot/sieve/
RUN rm -rf /etc/dovecot/conf.d \
 && sievec /etc/dovecot/sieve/before.sieve
COPY entrypoint.sh /entrypoint.sh

EXPOSE 25 465 587 993
HEALTHCHECK --interval=30s --timeout=5s --start-period=60s \
  CMD postfix status >/dev/null 2>&1 && doveadm process status >/dev/null 2>&1 || exit 1
ENTRYPOINT ["/entrypoint.sh"]
