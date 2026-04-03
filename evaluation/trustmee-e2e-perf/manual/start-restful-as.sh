#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib/common.sh
source "$SCRIPT_DIR/../lib/common.sh"

usage() {
    cat <<'EOF'
Usage: start-restful-as.sh [--port <port>] [--work-root <dir>] [--release]

Starts Attestation Service with:
  --features "restful-bin,snp-verifier,wasm-verification-component-driver"

Defaults:
  --port      8080
  --work-root evaluation/trustmee-e2e-perf/results/manual/as
EOF
}

PORT=8080
WORK_ROOT="$DEFAULT_RESULTS_ROOT/manual/as"
USE_RELEASE=0

while (($# > 0)); do
    case "$1" in
        --port)
            (($# >= 2)) || die "--port requires a value"
            PORT="$2"
            shift 2
            ;;
        --work-root)
            (($# >= 2)) || die "--work-root requires a value"
            WORK_ROOT="$2"
            shift 2
            ;;
        --release)
            USE_RELEASE=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            die "unknown argument: $1"
            ;;
    esac
done

ensure_common_prereqs

WORK_ROOT="$(ensure_directory_absolute "$WORK_ROOT")"
BINARY_PATH="$(build_restful_as "$USE_RELEASE")"
CONFIG_PATH="$(write_as_config "$WORK_ROOT")"

log_note "starting restful-as on http://127.0.0.1:$PORT"
log_note "work root: $WORK_ROOT"
log_note "config: $CONFIG_PATH"

cd "$WORK_ROOT"

exec env RUST_LOG="${RUST_LOG:-info,restful_as=debug,attestation_service=info}" \
    "$BINARY_PATH" \
    --config-file "$CONFIG_PATH" \
    --socket "127.0.0.1:$PORT"
