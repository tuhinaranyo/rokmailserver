#!/bin/sh
# Backs up the database (consistent dump), mailboxes, DKIM keys, SRS secret and .env
# to a restic repository, then prunes to 7 daily + 4 weekly snapshots.
# restic runs from its own pinned image, so nothing but Docker is needed on the host.
#
# Repository settings are read from deploy/.env (or the environment):
#   RESTIC_REPOSITORY  e.g. s3:https://s3.ap-southeast-1.amazonaws.com/bucket/rokmail
#   RESTIC_PASSWORD, AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY  (values without quotes)
# Optional: RESTIC_DOCKER_ARGS (extra `docker run` args, e.g. "-v /srv/repo:/repo" for a local repo).
#
# Run daily from cron:  15 3 * * *  /opt/rokmail/scripts/backup.sh >>/var/log/rokmail-backup.log 2>&1
set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
ENV_FILE=${ENV_FILE:-$ROOT/deploy/.env}
COMPOSE="docker compose -f $ROOT/deploy/docker-compose.yml --env-file $ENV_FILE"
PROJECT=${COMPOSE_PROJECT_NAME:-rokmail}
RESTIC_IMAGE=restic/restic:0.18.0

[ -f "$ENV_FILE" ] || { echo "missing $ENV_FILE" >&2; exit 1; }

# Read selected keys from .env without sourcing it (values may contain shell characters).
for k in RESTIC_REPOSITORY RESTIC_PASSWORD AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_DEFAULT_REGION RESTIC_DOCKER_ARGS; do
  eval "cur=\${$k:-}"
  if [ -z "$cur" ]; then
    val=$(sed -n "s/^$k=//p" "$ENV_FILE" | tail -n 1)
    [ -n "$val" ] && export "$k=$val"
  fi
done
: "${RESTIC_REPOSITORY:?RESTIC_REPOSITORY is not set (deploy/.env or environment)}"
: "${RESTIC_PASSWORD:?RESTIC_PASSWORD is not set (deploy/.env or environment)}"
export RESTIC_REPOSITORY RESTIC_PASSWORD

restic() {
  # shellcheck disable=SC2086
  docker run --rm --hostname rokmail-backup \
    -e RESTIC_REPOSITORY -e RESTIC_PASSWORD -e AWS_ACCESS_KEY_ID -e AWS_SECRET_ACCESS_KEY -e AWS_DEFAULT_REGION \
    ${RESTIC_DOCKER_ARGS:-} \
    -v "${PROJECT}_db:/data/db" -v "${PROJECT}_maildata:/data/maildata:ro" \
    -v "${PROJECT}_dkim:/data/dkim:ro" -v "${PROJECT}_mail_state:/data/mail_state:ro" \
    -v "$ENV_FILE:/data/env/.env:ro" \
    "$RESTIC_IMAGE" "$@"
}
# Shell inside the restic image (Alpine) for housekeeping in the db volume.
dbshell() { docker run --rm --entrypoint sh -v "${PROJECT}_db:/data/db" "$RESTIC_IMAGE" -c "$1"; }

STAMP=$(date +%Y%m%d-%H%M%S)
echo "[backup] $(date -u +%FT%TZ) dumping the database"
dbshell 'mkdir -p /data/db/backups'
# `run` starts a throwaway container from the admin image; it works with the admin service stopped.
$COMPOSE run --rm --no-deps admin backup-db "/db/backups/mail-$STAMP.db"

echo "[backup] uploading with restic"
restic snapshots >/dev/null 2>&1 || restic init
restic backup --tag rokmail --exclude-caches \
  /data/db/backups /data/maildata /data/dkim /data/mail_state /data/env
restic forget --tag rokmail --keep-daily 7 --keep-weekly 4 --prune

# Keep only the newest dump in the volume; restic holds the history.
dbshell 'ls -1t /data/db/backups/mail-*.db | tail -n +2 | xargs -r rm -f'
echo "[backup] done"
