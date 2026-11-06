#!/usr/bin/env bash
set -Eeuo pipefail

PGDATA="${PGDATA:-/var/lib/postgresql/data}"
POSTGRES_USER="${POSTGRES_USER:-artex}"
POSTGRES_PASSWORD="${POSTGRES_PASSWORD:-artex}"
POSTGRES_DB="${POSTGRES_DB:-artex}"
POSTGRES_PORT="${POSTGRES_PORT:-5432}"
postgres_started=0

pg_bin_dir="$(dirname "$(find /usr/lib/postgresql -mindepth 3 -maxdepth 3 -type f -name initdb | sort -V | tail -1)")"
export PATH="$pg_bin_dir:$PATH"

mkdir -p "$PGDATA" /app/data /workspaces /var/log/postgresql /var/run/postgresql
chown -R postgres:postgres "$PGDATA" /var/log/postgresql /var/run/postgresql

worker_config_root=/app/data/.worker-config
if [ -d "$worker_config_root/codex" ]; then
  mkdir -p /root/.config /root/.local/share
  if [ -L /root/.codex ] || [ ! -e /root/.codex ]; then
    ln -sfn "$worker_config_root/codex" /root/.codex
  fi
fi
if [ -d "$worker_config_root/opencode/config" ]; then
  if [ -L /root/.config/opencode ] || [ ! -e /root/.config/opencode ]; then
    ln -sfn "$worker_config_root/opencode/config" /root/.config/opencode
  fi
fi
if [ -d "$worker_config_root/opencode/data" ]; then
  if [ -L /root/.local/share/opencode ] || [ ! -e /root/.local/share/opencode ]; then
    ln -sfn "$worker_config_root/opencode/data" /root/.local/share/opencode
  fi
fi

if [ -d /opt/ctf-super-hub ]; then
  if [ ! -d /root/.codex/skills/ctf-super-hub ]; then
    /opt/ctf-super-hub/install-to-codex.sh /root/.codex/skills
  fi
  if [ ! -d /root/.config/opencode/skills/ctf-super-hub ]; then
    mkdir -p /root/.config/opencode/skills
    cp -R /opt/ctf-super-hub/{brainstorming,solve-challenge,ctf-*,strix-*} /root/.config/opencode/skills/
  fi
fi

if [ -z "${ARTEX_PG_DSN:-}" ]; then
if [ ! -s "$PGDATA/PG_VERSION" ]; then
  chmod 700 "$PGDATA"
  runuser -u postgres -- initdb -D "$PGDATA" --username=postgres --auth=trust
fi

runuser -u postgres -- pg_ctl -D "$PGDATA" \
  -l /var/log/postgresql/artex-postgresql.log \
  -o "-c listen_addresses=127.0.0.1 -p ${POSTGRES_PORT}" -w start
postgres_started=1

for attempt in $(seq 1 30); do
  if pg_isready -h 127.0.0.1 -p "$POSTGRES_PORT" -U postgres >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

role_exists="$(psql -h 127.0.0.1 -p "$POSTGRES_PORT" -U postgres -d postgres -Atq \
  -v user="$POSTGRES_USER" <<'SQL'
SELECT 1 FROM pg_roles WHERE rolname = :'user';
SQL
)"

if [ "$role_exists" != "1" ]; then
  psql -h 127.0.0.1 -p "$POSTGRES_PORT" -U postgres -d postgres -v ON_ERROR_STOP=1 \
    -v user="$POSTGRES_USER" -v password="$POSTGRES_PASSWORD" <<'SQL'
CREATE ROLE :"user" LOGIN PASSWORD :'password';
SQL
else
  psql -h 127.0.0.1 -p "$POSTGRES_PORT" -U postgres -d postgres -v ON_ERROR_STOP=1 \
    -v user="$POSTGRES_USER" -v password="$POSTGRES_PASSWORD" \
    <<'SQL'
ALTER ROLE :"user" WITH LOGIN PASSWORD :'password';
SQL
fi

database_exists="$(psql -h 127.0.0.1 -p "$POSTGRES_PORT" -U postgres -d postgres -Atq \
  -v database="$POSTGRES_DB" <<'SQL'
SELECT 1 FROM pg_database WHERE datname = :'database';
SQL
)"

if [ "$database_exists" != "1" ]; then
  psql -h 127.0.0.1 -p "$POSTGRES_PORT" -U postgres -d postgres -v ON_ERROR_STOP=1 \
    -v owner="$POSTGRES_USER" -v database="$POSTGRES_DB" <<'SQL'
CREATE DATABASE :"database" OWNER :"owner";
SQL
fi

export ARTEX_PG_DSN="postgres://${POSTGRES_USER}:${POSTGRES_PASSWORD}@127.0.0.1:${POSTGRES_PORT}/${POSTGRES_DB}?sslmode=disable"
else
  echo "[pg] using external ARTEX_PG_DSN"
fi
export ARTEX_AUDIT_LOCAL_ROOTS="${ARTEX_AUDIT_LOCAL_ROOTS:-/workspaces}"

/app/start.sh "$@" &
child=$!

shutdown() {
  kill -TERM "$child" 2>/dev/null || true
  wait "$child" 2>/dev/null || true
  if [ "$postgres_started" = "1" ]; then
    runuser -u postgres -- pg_ctl -D "$PGDATA" -m fast -w stop 2>/dev/null || true
  fi
  exit 0
}

trap shutdown INT TERM
wait "$child"
exit_code=$?
if [ "$postgres_started" = "1" ]; then
  runuser -u postgres -- pg_ctl -D "$PGDATA" -m fast -w stop 2>/dev/null || true
fi
exit "$exit_code"
