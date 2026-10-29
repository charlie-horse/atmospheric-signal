#!/usr/bin/env bash
# One-time install + build of the local ATProto stack. Idempotent: re-running
# skips anything already present at the pinned revision.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/env.sh"

mkdir -p "$VENDOR/bin" "$VENDOR/logs"
BUILD_LOGS="$VENDOR/logs"

# ---------------------------------------------------------------- apt
need_pkgs=()
[[ -x $PG_BIN/initdb ]] || need_pkgs+=("postgresql-$PG_VERSION")
command -v protoc >/dev/null || need_pkgs+=(protobuf-compiler)
command -v pkg-config >/dev/null || need_pkgs+=(pkg-config)
dpkg -s libssl-dev >/dev/null 2>&1 || need_pkgs+=(libssl-dev)
command -v clang >/dev/null || need_pkgs+=(clang)
command -v git >/dev/null || need_pkgs+=(git)
command -v curl >/dev/null || need_pkgs+=(curl)
if ((${#need_pkgs[@]})); then
  log "apt install ${need_pkgs[*]}"
  export DEBIAN_FRONTEND=noninteractive
  apt-get install -y -q "${need_pkgs[@]}" || { apt-get update -q && apt-get install -y -q "${need_pkgs[@]}"; }
fi
# Debian's postgresql package auto-creates a cluster on 5432; we never use it.
for t in go node cargo rustup npm; do command -v $t >/dev/null || die "missing $t (need Go >=1.24, Node >=22.18, rustup)"; done

# ---------------------------------------------------------------- clones
clone_at() { # dir repo rev [tag]
  local dir=$1 repo=$2 rev=$3 tag=${4:-}
  if [[ -d $dir/.git ]] && [[ $(git -C "$dir" rev-parse HEAD) == "$rev" ]]; then
    log "$(basename "$dir") already at $rev"; return
  fi
  if [[ ! -d $dir/.git ]]; then
    log "cloning $repo"
    if [[ -n $tag ]]; then
      git clone -q --branch "$tag" "$repo" "$dir"
    else
      git clone -q "$repo" "$dir"
    fi
  fi
  git -C "$dir" fetch -q --tags origin 2>/dev/null || true
  git -C "$dir" -c advice.detachedHead=false checkout -q "$rev"
  [[ $(git -C "$dir" rev-parse HEAD) == "$rev" ]] || die "$dir: could not check out $rev"
}
clone_at "$VENDOR/did-method-plc" "$PLC_REPO" "$PLC_REV"
clone_at "$VENDOR/tranquil-pds" "$TRANQUIL_REPO" "$TRANQUIL_REV" "$TRANQUIL_TAG"
clone_at "$VENDOR/indigo" "$INDIGO_REPO" "$INDIGO_REV"

# Local patches (see README "Quirks"). Applied once; a no-op if already applied.
apply_patch() { # dir patch
  if git -C "$1" apply --reverse --check "$2" 2>/dev/null; then
    log "patch $(basename "$2") already applied"
  else
    log "applying $(basename "$2")"
    git -C "$1" apply "$2"
    rm -f "$VENDOR/bin/.relay-"* "$VENDOR/tranquil-pds/target/release/.built-"* # force rebuild
  fi
}
apply_patch "$VENDOR/indigo" "$STACK_DIR/patches/indigo-relay-localhost-hostcheck.patch"
apply_patch "$VENDOR/tranquil-pds" "$STACK_DIR/patches/tranquil-localhost-http-endpoint.patch"

# ---------------------------------------------------------------- builds (parallel)
pids=()

build_relay() {
  local stamp="$VENDOR/bin/.relay-$INDIGO_REV"
  [[ -x $RELAY_BIN && -f $stamp ]] && { log "relay already built"; return; }
  log "building indigo relay (go) -> $BUILD_LOGS/relay.log"
  (cd "$VENDOR/indigo" && go build -o "$RELAY_BIN" ./cmd/relay) >"$BUILD_LOGS/relay.log" 2>&1
  touch "$stamp"
}

build_plc() {
  local stamp="$PLC_SERVER_DIR/dist/.built-$PLC_REV"
  [[ -f $stamp ]] && { log "plc already built"; return; }
  if [[ ! -x $PNPM ]]; then
    # PLC's package.json devEngines hard-requires pnpm $PNPM_VERSION; install it locally.
    mkdir -p "$VENDOR/tools"
    npm install --silent --no-audit --no-fund --prefix "$VENDOR/tools" "pnpm@$PNPM_VERSION"
  fi
  log "building did-method-plc (pnpm) -> $BUILD_LOGS/plc.log"
  (cd "$VENDOR/did-method-plc" && "$PNPM" install --frozen-lockfile && "$PNPM" run build) >"$BUILD_LOGS/plc.log" 2>&1
  touch "$stamp"
}

build_tranquil() {
  local stamp="$VENDOR/tranquil-pds/target/release/.built-$TRANQUIL_REV"
  [[ -x $TRANQUIL_BIN && -f $stamp ]] && { log "tranquil already built"; return; }
  rustup toolchain list | grep -q "^$RUST_TOOLCHAIN" || rustup toolchain install "$RUST_TOOLCHAIN" --profile minimal
  log "building tranquil-server (cargo --release, ~10-20 min) -> $BUILD_LOGS/tranquil.log"
  (cd "$VENDOR/tranquil-pds" && SQLX_OFFLINE=true cargo build --release -p tranquil-server) >"$BUILD_LOGS/tranquil.log" 2>&1
  touch "$stamp"
}

build_relay & pids+=($!)
build_plc & pids+=($!)
build_tranquil & pids+=($!)
fail=0
for p in "${pids[@]}"; do wait "$p" || fail=1; done
((fail == 0)) || die "a build failed; see $BUILD_LOGS/*.log"

# ---------------------------------------------------------------- smoke deps
if [[ ! -d $STACK_DIR/node_modules/@atproto/sync ]]; then
  log "npm install (smoke test deps)"
  (cd "$STACK_DIR" && npm install --no-audit --no-fund)
fi

log "setup complete. Next: ./up.sh"
