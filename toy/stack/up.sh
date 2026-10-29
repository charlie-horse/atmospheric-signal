#!/usr/bin/env bash
# Start Postgres, PLC, Tranquil PDS and the indigo relay in the background.
# Idempotent: already-running pieces are left alone.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/env.sh"

[[ -x $RELAY_BIN && -x $TRANQUIL_BIN && -f $PLC_SERVER_DIR/dist/bin.js ]] || die "not built yet; run ./setup.sh"

mkdir -p "$LOGS" "$RUN" "$DATA/tranquil/store" "$DATA/tranquil/blobs" "$DATA/relay/persist"

# ---------------------------------------------------------------- secrets (generated once per data dir)
SECRETS="$DATA/secrets.env"
if [[ ! -f $SECRETS ]]; then
  umask 077
  {
    echo "JWT_SECRET=$(openssl rand -hex 32)"
    echo "DPOP_SECRET=$(openssl rand -hex 32)"
    echo "MASTER_KEY=$(openssl rand -hex 32)"
    echo "RELAY_ADMIN_PASSWORD=$(openssl rand -hex 16)"
  } >"$SECRETS"
  umask 022
fi
# shellcheck disable=SC1090
source "$SECRETS"

# Start a daemon with a clean environment (so e.g. DATABASE_URL never leaks
# between services). Usage: start_daemon name workdir VAR=val ... -- cmd args...
start_daemon() {
  local name=$1 dir=$2; shift 2
  local envs=()
  while [[ $1 != -- ]]; do envs+=("$1"); shift; done; shift
  if pid_alive "$name"; then log "$name already running (pid $(cat "$RUN/$name.pid"))"; return 1; fi
  log "starting $name -> $LOGS/$name.log"
  (cd "$dir" && exec setsid env -i PATH="$PATH" HOME="$HOME" "${envs[@]}" "$@" >>"$LOGS/$name.log" 2>&1 </dev/null) &
  echo $! >"$RUN/$name.pid"
}

# ---------------------------------------------------------------- postgres (for PLC only)
if [[ ! -f $PG_DATA/PG_VERSION ]]; then
  log "initdb $PG_DATA"
  mkdir -p "$PG_DATA" && chown postgres:postgres "$PG_DATA" && chmod 700 "$PG_DATA"
  as_pg "$PG_BIN/initdb" -D "$PG_DATA" -U postgres -A trust -E UTF8 >"$LOGS/initdb.log"
fi
mkdir -p "$PG_SOCK" && chown postgres:postgres "$PG_SOCK"
touch "$LOGS/postgres.log" && chown postgres:postgres "$LOGS/postgres.log"
if as_pg "$PG_BIN/pg_ctl" -D "$PG_DATA" status >/dev/null 2>&1; then
  log "postgres already running"
else
  log "starting postgres on 127.0.0.1:$PG_PORT"
  as_pg "$PG_BIN/pg_ctl" -D "$PG_DATA" -l "$LOGS/postgres.log" -w -t 30 \
    -o "-p $PG_PORT -c listen_addresses=127.0.0.1 -k $PG_SOCK" start >/dev/null
fi
psql_pg() { as_pg psql -h "$PG_SOCK" -p "$PG_PORT" -U postgres -tAq "$@"; }
[[ $(psql_pg -c "select 1 from pg_roles where rolname='plc'") == 1 ]] || psql_pg -c "create role plc login password 'plc'"
[[ $(psql_pg -c "select 1 from pg_database where datname='plc'") == 1 ]] || psql_pg -c "create database plc owner plc"

# ---------------------------------------------------------------- PLC directory
if ! curl -fs -o /dev/null --max-time 2 "$PLC_URL/_health"; then
  start_daemon plc "$PLC_SERVER_DIR" \
    DATABASE_URL="$PLC_DB_URL" PORT="$PLC_PORT" LOG_ENABLED=true LOG_LEVEL=info \
    -- node --enable-source-maps dist/bin.js || true
  wait_http plc "$PLC_URL/_health" 60 plc
fi
log "plc healthy"

# ---------------------------------------------------------------- Tranquil PDS
# DATABASE_URL is a required config key even with REPO_BACKEND=tranquil-store,
# but it is only dialled for the postgres backend, so a dummy value is fine.
if ! curl -fs -o /dev/null --max-time 2 "$PDS_URL/xrpc/_health"; then
  start_daemon tranquil "$DATA/tranquil" \
    RUST_LOG="${RUST_LOG:-info}" \
    PDS_HOSTNAME="localhost:$PDS_PORT" SERVER_HOST=127.0.0.1 SERVER_PORT="$PDS_PORT" \
    PDS_USER_HANDLE_DOMAINS="$HANDLE_DOMAIN" \
    PLC_DIRECTORY_URL="$PLC_URL" \
    REPO_BACKEND=tranquil-store TRANQUIL_STORE_DATA_DIR="$DATA/tranquil/store" \
    DATABASE_URL=postgres://unused@127.0.0.1:1/unused \
    BLOB_STORAGE_BACKEND=filesystem BLOB_STORAGE_PATH="$DATA/tranquil/blobs" \
    INVITE_CODE_REQUIRED=false DISABLE_ACCOUNT_VERIFICATION_GATE=true \
    DISABLE_RATE_LIMITING=true ALLOW_PRIVATE_FETCH=true ALLOW_HTTP_PROXY=true \
    ENABLE_CADDY_ON_DEMAND_TLS=false FRONTEND_ENABLED=false \
    PDS_AGE_ASSURANCE_OVERRIDE=true \
    TRANQUIL_PDS_ALLOW_INSECURE_SECRETS=true \
    JWT_SECRET="$JWT_SECRET" DPOP_SECRET="$DPOP_SECRET" MASTER_KEY="$MASTER_KEY" \
    CRAWLERS="$RELAY_HTTP" \
    -- "$TRANQUIL_BIN" || true
  wait_http tranquil "$PDS_URL/xrpc/_health" 90 tranquil
fi
log "tranquil healthy"

# ---------------------------------------------------------------- indigo relay
if ! curl -fs -o /dev/null --max-time 2 "$RELAY_HTTP/xrpc/_health"; then
  start_daemon relay "$DATA/relay" \
    RELAY_ADMIN_PASSWORD="$RELAY_ADMIN_PASSWORD" RELAY_PLC_HOST="$PLC_URL" \
    DATABASE_URL="sqlite://$DATA/relay/relay.sqlite" RELAY_PERSIST_DIR="$DATA/relay/persist" \
    RELAY_API_BIND=":$RELAY_PORT" RELAY_METRICS_LISTEN="127.0.0.1:2471" \
    RELAY_DISABLE_REQUEST_CRAWL=true RELAY_ALLOW_INSECURE_HOSTS=true \
    RELAY_LENIENT_SYNC_VALIDATION=true LOG_LEVEL=info \
    -- "$RELAY_BIN" serve || true
  wait_http relay "$RELAY_HTTP/xrpc/_health" 60 relay
fi
log "relay healthy"

# Register the PDS with the relay (admin requestCrawl allows localhost + http).
if curl -fsS -u "admin:$RELAY_ADMIN_PASSWORD" "$RELAY_HTTP/admin/pds/list" | grep -q "\"localhost:$PDS_PORT\""; then
  log "relay already subscribed to localhost:$PDS_PORT"
else
  log "registering localhost:$PDS_PORT with the relay"
  curl -fsS -u "admin:$RELAY_ADMIN_PASSWORD" -XPOST "$RELAY_HTTP/admin/pds/requestCrawl" \
    -H 'content-type: application/json' -d "{\"hostname\":\"http://localhost:$PDS_PORT\"}" >/dev/null \
    || die "requestCrawl failed; see $LOGS/relay.log"
fi

cat <<EOF

  PLC directory   $PLC_URL
  Tranquil PDS    $PDS_URL      (handles: <name>.$HANDLE_DOMAIN, email required)
  Relay firehose  $RELAY_URL/xrpc/com.atproto.sync.subscribeRepos
  Relay admin     $RELAY_HTTP/admin  (user admin, password in $SECRETS)
  Postgres (PLC)  127.0.0.1:$PG_PORT
  Logs            $LOGS/

EOF
