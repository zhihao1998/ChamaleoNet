#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONF_FILE="${BFR_CONTROLLER_CONF:-$ROOT/conf/controller.env}"

if [[ -f "$CONF_FILE" ]]; then
  # shellcheck disable=SC1090
  source "$CONF_FILE"
fi

P4_RULE_SHM_NAME="${P4_RULE_SHM_NAME:-/p4_rule_ring}"
export P4_RULE_SHM_NAME

EXTRA_ARGS="${BFR_CONTROLLER_ARGS:-}"

exec python3 "$ROOT/bfrt_grpc/bfrt_controller.py" --shm-name "$P4_RULE_SHM_NAME" ${EXTRA_ARGS} "$@"
