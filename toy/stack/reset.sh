#!/usr/bin/env bash
# Stop everything and wipe all runtime data (accounts, PLC ops, relay state,
# secrets, logs). Builds in vendor/ are kept. Run ./up.sh afterwards.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/env.sh"
"$STACK_DIR/down.sh"
[[ $DATA == */data ]] || die "refusing to wipe unexpected DATA=$DATA"
log "wiping $DATA"
rm -rf "$DATA"
log "reset done; run ./up.sh"
