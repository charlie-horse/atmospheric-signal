# Shared settings for setup.sh / up.sh / down.sh / reset.sh. Sourced, not executed.
# shellcheck shell=bash

STACK_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENDOR="${ATSIG_STACK_VENDOR:-$STACK_DIR/vendor}"
DATA="${ATSIG_STACK_DATA:-$STACK_DIR/data}"
LOGS="$DATA/logs"
RUN="$DATA/run"

# ---- pinned sources (keep in sync with VERSIONS.md) ----
PLC_REPO=https://github.com/did-method-plc/did-method-plc
PLC_REV=29f1a70ee9f6f80a25946cac103b2f745e371334
TRANQUIL_REPO=https://tangled.org/tranquil.farm/tranquil-pds
TRANQUIL_TAG=v0.7.1
TRANQUIL_REV=4e5ded7de520e4cc38ab54e70abb60ecb5f86d60
INDIGO_REPO=https://github.com/bluesky-social/indigo
INDIGO_REV=51095abf6e9597f041bd510d02ff6a20376f581e
PNPM_VERSION=11.11.0
RUST_TOOLCHAIN=1.96.0   # from tranquil-pds/rust-toolchain.toml

# ---- binaries ----
PNPM="$VENDOR/tools/node_modules/.bin/pnpm"
RELAY_BIN="$VENDOR/bin/relay"
TRANQUIL_BIN="$VENDOR/tranquil-pds/target/release/tranquil-server"
PLC_SERVER_DIR="$VENDOR/did-method-plc/packages/server"
PG_VERSION="${PG_VERSION:-16}"
PG_BIN="/usr/lib/postgresql/$PG_VERSION/bin"

# ---- ports / endpoints (must match toy/CONTRACT.md) ----
PG_PORT="${ATSIG_PG_PORT:-5442}"   # not 5432, to stay out of the way of any system postgres
PLC_PORT=2582
PDS_PORT=3000
RELAY_PORT=2470
PLC_URL="http://localhost:$PLC_PORT"
PDS_URL="http://localhost:$PDS_PORT"
RELAY_URL="ws://localhost:$RELAY_PORT"
RELAY_HTTP="http://localhost:$RELAY_PORT"
HANDLE_DOMAIN=test                  # accounts are <name>.test
PLC_DB_URL="postgres://plc:plc@127.0.0.1:$PG_PORT/plc"

PG_DATA="$DATA/pg"
PG_SOCK="$DATA/pg-run"

log() { printf '\033[1;34m[stack]\033[0m %s\n' "$*"; }
die() { printf '\033[1;31m[stack]\033[0m %s\n' "$*" >&2; exit 1; }

as_pg() { runuser -u postgres -- "$@"; }

pid_alive() { # name
  local f="$RUN/$1.pid"
  [[ -f $f ]] && kill -0 "$(cat "$f")" 2>/dev/null
}

wait_http() { # name url timeout_s
  local name=$1 url=$2 t=${3:-60} i
  for ((i = 0; i < t * 2; i++)); do
    if curl -fs -o /dev/null --max-time 2 "$url"; then return 0; fi
    if [[ -n ${4:-} ]] && ! pid_alive "$4"; then
      die "$name exited during startup; see $LOGS/$4.log"
    fi
    sleep 0.5
  done
  die "$name not healthy at $url after ${t}s; see $LOGS"
}
