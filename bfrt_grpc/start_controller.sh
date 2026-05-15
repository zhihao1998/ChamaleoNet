#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TSDN_COMMON_CONF="${TSDN_COMMON_CONF:-$ROOT/conf/controller.env}"

load_common_conf() {
  if [[ -f "$TSDN_COMMON_CONF" ]]; then
    set -a
    # shellcheck source=/dev/null
    source "$TSDN_COMMON_CONF"
    set +a
  fi
}

load_common_conf

P4_RULE_SHM_NAME="${P4_RULE_SHM_NAME:-/p4_rule_ring}"
export P4_RULE_SHM_NAME

# BF / controller tunables (can be overridden in env or shared conf)
BFR_EPOCH_SWITCH_SEC="${BFR_EPOCH_SWITCH_SEC:-5}"
BFR_HOT_WINDOW="${BFR_HOT_WINDOW:-2}"
BFR_EPOCH_PRINT_SEC="${BFR_EPOCH_PRINT_SEC:-10}"
BFR_ENTRY_TTL_MS="${BFR_ENTRY_TTL_MS:-5000}"
BFR_SOCK_PATH="${BFR_SOCK_PATH:-/tmp/p4_controller.sock}"
BFR_UPDATE_MODE="${BFR_UPDATE_MODE:-${TSDN_UPDATE_MODE:-both}}"
BFR_INSTALL_BATCH_SIZE="${BFR_INSTALL_BATCH_SIZE:-1024}"
BFR_INSTALL_BATCH_MIN="${BFR_INSTALL_BATCH_MIN:-256}"
BFR_INSTALL_CALL_TARGET_MS="${BFR_INSTALL_CALL_TARGET_MS:-120}"
BFR_INSTALL_BACKLOG_BATCHES="${BFR_INSTALL_BACKLOG_BATCHES:-12}"
BFR_INSTALL_BACKLOG_HIGH_WATERMARK="${BFR_INSTALL_BACKLOG_HIGH_WATERMARK:-20000}"
BFR_INSTALL_BUDGET_MS="${BFR_INSTALL_BUDGET_MS:-900}"
BFR_HW_SAMPLE_INTERVAL_MS="${BFR_HW_SAMPLE_INTERVAL_MS:-10000}"
BFR_FAILED_CLEAN_INTERVAL_MS="${BFR_FAILED_CLEAN_INTERVAL_MS:-200}"
BFR_FAILED_CLEAN_SCAN_BATCH="${BFR_FAILED_CLEAN_SCAN_BATCH:-1024}"
BFR_IDLE_CLEAN_INTERVAL_MS="${BFR_IDLE_CLEAN_INTERVAL_MS:-200}"
BFR_IDLE_CLEAN_SKIP_PENDING="${BFR_IDLE_CLEAN_SKIP_PENDING:-4096}"
BFR_INSTALL_FALLBACK_SINGLE="${BFR_INSTALL_FALLBACK_SINGLE:-0}"

case "$BFR_UPDATE_MODE" in
  both|rules-only) ;;
  *)
    echo "error: BFR_UPDATE_MODE must be 'both' or 'rules-only', got: $BFR_UPDATE_MODE" >&2
    exit 1
    ;;
esac

BASE_ARGS=(
  --shm-name "$P4_RULE_SHM_NAME"
  --epoch-switch "$BFR_EPOCH_SWITCH_SEC"
  --hot-window "$BFR_HOT_WINDOW"
  --epoch-print "$BFR_EPOCH_PRINT_SEC"
  --entry-ttl "$BFR_ENTRY_TTL_MS"
  --sock "$BFR_SOCK_PATH"
  --update-mode "$BFR_UPDATE_MODE"
  --install-batch-size "$BFR_INSTALL_BATCH_SIZE"
  --install-batch-min "$BFR_INSTALL_BATCH_MIN"
  --install-call-target-ms "$BFR_INSTALL_CALL_TARGET_MS"
  --install-backlog-batches "$BFR_INSTALL_BACKLOG_BATCHES"
  --install-backlog-high-watermark "$BFR_INSTALL_BACKLOG_HIGH_WATERMARK"
  --install-budget-ms "$BFR_INSTALL_BUDGET_MS"
  --hw-sample-interval-ms "$BFR_HW_SAMPLE_INTERVAL_MS"
  --failed-clean-interval-ms "$BFR_FAILED_CLEAN_INTERVAL_MS"
  --failed-clean-scan-batch "$BFR_FAILED_CLEAN_SCAN_BATCH"
  --idle-clean-interval-ms "$BFR_IDLE_CLEAN_INTERVAL_MS"
  --idle-clean-skip-pending "$BFR_IDLE_CLEAN_SKIP_PENDING"
)

if [[ "$BFR_INSTALL_FALLBACK_SINGLE" == "1" ]]; then
  BASE_ARGS+=(--install-fallback-single)
fi

EXTRA_ARGS="${BFR_CONTROLLER_ARGS:-}"

exec python3 "$ROOT/bfrt_grpc/bfrt_controller.py" "${BASE_ARGS[@]}" ${EXTRA_ARGS} "$@"
