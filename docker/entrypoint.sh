#!/bin/sh
set -e
# Runs as root only long enough to make /app/data writable, then drops to PUID:PGID.
# Defaults suit Unraid (nobody:users = 99:100). Set PUID/PGID to match your host folder.
PUID="${PUID:-99}"
PGID="${PGID:-100}"

mkdir -p /app/data
if [ "$(id -u)" = "0" ]; then
  chown -R "$PUID:$PGID" /app/data
  exec su-exec "$PUID:$PGID" "$@"
fi

if [ ! -w /app/data ]; then
  echo "ERROR: /app/data is not writable by uid $(id -u). Fix the volume permissions or set PUID/PGID." >&2
  exit 1
fi
exec "$@"
