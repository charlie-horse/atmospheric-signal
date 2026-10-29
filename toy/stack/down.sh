#!/usr/bin/env bash
# Stop relay, Tranquil, PLC and Postgres. Data is kept.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/env.sh"

stop_daemon() { # name
  local f="$RUN/$1.pid" pid i
  [[ -f $f ]] || return 0
  pid=$(cat "$f")
  if kill -0 "$pid" 2>/dev/null; then
    log "stopping $1 (pid $pid)"
    kill -TERM -- "-$pid" 2>/dev/null || kill -TERM "$pid" 2>/dev/null || true
    for ((i = 0; i < 40; i++)); do kill -0 "$pid" 2>/dev/null || break; sleep 0.25; done
    if kill -0 "$pid" 2>/dev/null; then
      log "$1 did not exit, sending SIGKILL"
      kill -KILL -- "-$pid" 2>/dev/null || kill -KILL "$pid" 2>/dev/null || true
    fi
  fi
  rm -f "$f"
}

stop_daemon relay
stop_daemon tranquil
stop_daemon plc
if [[ -f $PG_DATA/PG_VERSION ]] && as_pg "$PG_BIN/pg_ctl" -D "$PG_DATA" status >/dev/null 2>&1; then
  log "stopping postgres"
  as_pg "$PG_BIN/pg_ctl" -D "$PG_DATA" -m fast -w stop >/dev/null
fi
log "stack stopped"
