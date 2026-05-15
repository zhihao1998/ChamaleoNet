#!/usr/bin/env bash
# Multi-interface launcher for tsdn: one `make`, N processes.
# Each `start` creates log/runs/<YYYYMMDD_HH-MM-SS>/ with stats CSVs and tsdn/<iface>.status;
# log/runs/latest → that run (for follow / status).
#
# Commands (see also ./tsdn-multi.sh --help):
#   start [--with-controller|-c] [iface ...]
#                       With no args: read conf/tsdn.interfaces (or TSDN_INTERFACES_FILE).
#   start-all [iface ...]  Start controller + one tsdn per interface (detached).
#   start-all-fg [iface ...]
#                       Start controller + tsdn in foreground monitor mode.
#   list                Print the interface list that a no-arg start would use.
#   follow | tail [-t|-c] follow tsdn/controller CSVs, never mixed.
#   watch | top         Dynamic refresh of per-iface *.status (same data as stderr lines).
#   stop | status       Kill or show this repo's tsdn/controller processes.
#
# Environment (optional):
#   TSDN_INTERFACES_FILE  Path to iface list (default: conf/tsdn.interfaces in repo root).
#                         Egress (static MACs only; see conf/tsdn.interfaces.example):
#                           collector <iface> <dst_mac>               (legacy)
#                           collector <iface> <src_mac> <dst_mac>     (preferred)
#                           switch_dst <aa:bb:cc:dd:ee:ff>
#   TSDN_COLLECTOR_INTF / TSDN_COLLECTOR_SRC_MAC / TSDN_COLLECTOR_DST_MAC / TSDN_SWITCH_DST_MAC
#                         Override file values when set.
#   TSDN_MAKE_CLEAN=1      Run make clean && make once before start.
#   TSDN_SKIP_MAKE=1       Do not run make before start.
#   TSDN_SKIP_IFUP=1       Skip "sudo ifconfig <iface> up" before each instance.
#   TSDN_WATCH_INTERVAL    Seconds between watch refreshes (default 1).
#   P4_RULE_SHM_NAME       SHM ring name for controller IPC (default /p4_rule_ring).

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TSDN_MULTI_SH="$(readlink -f "${BASH_SOURCE[0]}")"
BIN="$ROOT/bin/tsdn"
CTRL_START="$ROOT/bfrt_grpc/start_controller.sh"
RUNS_ROOT="$ROOT/log/runs"
LATEST_RUN_LINK="$RUNS_ROOT/latest"
IFACES_CONF="${TSDN_INTERFACES_FILE:-$ROOT/conf/tsdn.interfaces}"
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
TSDN_UPDATE_MODE="${TSDN_UPDATE_MODE:-rules-only}"
BFR_LOG_NAME="${BFR_LOG_NAME:-bfrt.log}"

validate_update_mode() {
	case "$TSDN_UPDATE_MODE" in
	both | rules-only) ;;
	*)
		echo "error: TSDN_UPDATE_MODE must be 'both' or 'rules-only', got: $TSDN_UPDATE_MODE" >&2
		exit 1
		;;
	esac
}

active_tsdn_dir() {
	if [[ -L "$LATEST_RUN_LINK" ]] && [[ -d "$(readlink -f "$LATEST_RUN_LINK")/tsdn" ]]; then
		readlink -f "$LATEST_RUN_LINK"
		return 0
	fi
	return 1
}

usage() {
	cat <<EOF
Multi-interface tsdn launcher (one build, N processes).

Each successful start creates: log/runs/<YYYYMMDD_HH-MM-SS>/{*.csv, tsdn/*.status}
Symlink log/runs/latest points at the last start (used by follow / status iface list).

Commands:
  start [--with-controller|-c] [iface ...]
                               no args: read $IFACES_CONF (default conf/tsdn.interfaces)
  start-all [iface ...]       start controller + tsdn workers in one run dir (detached)
  start-all-fg [iface ...]    start controller + tsdn workers; exit when any child exits
  list                        print interface list from config (same as bare start)
  stop [timeout_seconds]      TERM then KILL this repo's bin/tsdn (default timeout: 5s)
  status                      show matching processes
  follow | tail [--tsdn|-t|--controller|-c]
                               follow tsdn status (-t, default) or controller CSV (-c), not both
  watch | top                 watch(1) refresh of log/runs/latest/tsdn/*.status

Env: TSDN_INTERFACES_FILE=path   → default iface list file for "start" / "list"
     TSDN_COLLECTOR_INTF / TSDN_COLLECTOR_SRC_MAC / TSDN_COLLECTOR_DST_MAC / TSDN_SWITCH_DST_MAC
        → override egress MACs from conf/tsdn.interfaces
     TSDN_COMMON_CONF=path      → shared config file (default conf/controller.env)
     TSDN_MAKE_CLEAN=1  → make clean && make
     TSDN_SKIP_MAKE=1   → skip make before start
     TSDN_SKIP_IFUP=1   → skip ifconfig up before start
     TSDN_UPDATE_MODE=both|rules-only → both: bloom+rules, rules-only: rules only
     TSDN_STATS_LOG_SAMPLE_US=10000000 → tsdn stats/status interval in microseconds (e.g. 10s)
     TSDN_LOG_OUTPUT_MODE=debug|daemon → preset intervals (see bottom of conf/controller.env)
     TSDN_WATCH_INTERVAL=seconds → interval for watch (default 1)
     P4_RULE_SHM_NAME=/p4_rule_ring → shared ring name for rule IPC
EOF
}

# Parse conf: skip blank / comment lines; support multiple ifaces per line.
# Lines whose first field is "collector" or "switch_dst" are not capture ifaces.
read_ifaces_from_config() {
	local f="$1"
	if [[ ! -f "$f" ]]; then
		echo "error: interface list not found: $f" >&2
		echo "  cp $ROOT/conf/tsdn.interfaces.example $f" >&2
		echo "  edit $f, then: $0 start" >&2
		exit 1
	fi
	awk '!/^[[:space:]]*(#|$)/ && NF {
		if ($1 == "collector" || $1 == "switch_dst") next
		for (i = 1; i <= NF; i++) print $i
	}' "$f"
}

# First matching line:
#   collector <iface> <dst_mac>              (legacy)
#   collector <iface> <src_mac> <dst_mac>    (preferred)
# (dst MAC required unless TSDN_COLLECTOR_DST_MAC is set)
read_collector_from_config() {
	local f="$1"
	[[ -f "$f" ]] || return 0
	awk '!/^[[:space:]]*(#|$)/ && NF && $1 == "collector" && NF >= 3 {
		if (NF >= 4) print $2 "\t" $3 "\t" $4
		else print $2 "\t-\t" $3
		exit
	}' "$f"
}

# First matching line: switch_dst <aa:bb:cc:dd:ee:ff>  (required unless TSDN_SWITCH_DST_MAC is set)
read_switch_dst_from_config() {
	local f="$1"
	[[ -f "$f" ]] || return 0
	awk '!/^[[:space:]]*(#|$)/ && NF && $1 == "switch_dst" && NF >= 2 {
		print $2
		exit
	}' "$f"
}

resolve_start_ifaces() {
	local -a out
	if [[ $# -ge 1 ]]; then
		out=("$@")
	else
		mapfile -t out < <(read_ifaces_from_config "$IFACES_CONF")
	fi
	if [[ ${#out[@]} -eq 0 ]]; then
		echo "error: no interfaces (empty $IFACES_CONF or empty args)" >&2
		exit 1
	fi
	printf '%s\n' "${out[@]}"
}

cmd_list() {
	echo "config file: $IFACES_CONF"
	resolve_start_ifaces "$@"
}

bring_interfaces_up() {
	if [[ -n "${TSDN_SKIP_IFUP:-}" ]]; then
		return 0
	fi
	local iface
	for iface in "$@"; do
		echo "sudo ifconfig $iface up"
		sudo ifconfig "$iface" up
	done
}

cleanup_shm_ring() {
	local shm_name="$1"
	local shm_path="/dev/shm/${shm_name#/}"
	# Remove stale ring (often root-owned from previous runs with strict umask).
	# Ignore errors if it does not exist.
	sudo rm -f "$shm_path" 2>/dev/null || true
}

ensure_bin() {
	if [[ ! -x "$BIN" ]]; then
		echo "error: $BIN not found or not executable; run start with build enabled" >&2
		exit 1
	fi
}

do_make() {
	if [[ -n "${TSDN_SKIP_MAKE:-}" ]]; then
		return 0
	fi
(
	cd "$ROOT"
		if [[ -n "${TSDN_MAKE_CLEAN:-}" ]]; then
			make clean && make
		else
			make
		fi
	)
}

cmd_start_common() {
	local with_controller="${1:-0}"
	shift || true
	local run_foreground="${1:-0}"
	shift || true
	local -a ifaces
	mapfile -t ifaces < <(resolve_start_ifaces "$@")
	validate_update_mode

	local run_id log_run tsdn_dir ifaces_file ts
	run_id="$(date +%Y%m%d_%H-%M-%S)"
	log_run="$RUNS_ROOT/$run_id"
	tsdn_dir="$log_run/tsdn"
	mkdir -p "$tsdn_dir"
	ln -sfn "$log_run" "$LATEST_RUN_LINK"

	do_make
	ensure_bin

	ts="$(date -Iseconds)"
	ifaces_file="$tsdn_dir/interfaces.last"
	printf '%s\n' "${ifaces[@]}" >"$ifaces_file"
	{
		echo "# started $ts"
		echo "# run_dir $log_run"
		echo "# p4_rule_shm_name $P4_RULE_SHM_NAME"
		echo "# tsdn_update_mode $TSDN_UPDATE_MODE"
		printf '%s\n' "${ifaces[@]}"
	} >"$tsdn_dir/README-interfaces.txt"

	local coll_if="" coll_src_mac="" coll_mac=""
	local sw_mac=""
	local eff_coll_if eff_coll_src_mac eff_coll_mac eff_switch_mac
	local -a tsdn_env
	local -a child_pids=()

	if [[ -f "$IFACES_CONF" ]]; then
		IFS=$'\t' read -r coll_if coll_src_mac coll_mac < <(read_collector_from_config "$IFACES_CONF" || true)
		if [[ "${coll_src_mac:-}" == "-" ]]; then
			coll_src_mac=""
		fi
		sw_mac="$(read_switch_dst_from_config "$IFACES_CONF")"
	fi

	eff_coll_if="${TSDN_COLLECTOR_INTF:-$coll_if}"
	if [[ -z "$eff_coll_if" ]]; then
		echo "error: collector interface not set (add \"collector <iface> <dst_mac>\" or \"collector <iface> <src_mac> <dst_mac>\" to $IFACES_CONF, or export TSDN_COLLECTOR_INTF)" >&2
		exit 1
	fi

	local -a ifup_list=("${ifaces[@]}")
	ifup_list+=("$eff_coll_if")
	bring_interfaces_up "${ifup_list[@]}"

	eff_coll_src_mac="${TSDN_COLLECTOR_SRC_MAC:-$coll_src_mac}"
	if [[ -n "$eff_coll_src_mac" ]]; then
		if ! [[ "$eff_coll_src_mac" =~ ^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$ ]]; then
			echo "error: invalid collector source MAC (expected aa:bb:cc:dd:ee:ff): $eff_coll_src_mac" >&2
			exit 1
		fi
	fi

	if [[ -n "${TSDN_COLLECTOR_DST_MAC:-}" ]]; then
		eff_coll_mac="$TSDN_COLLECTOR_DST_MAC"
	else
		if [[ -z "${coll_mac:-}" ]]; then
			echo "error: collector destination MAC missing (add \"collector <iface> <dst_mac>\" or \"collector <iface> <src_mac> <dst_mac>\" to $IFACES_CONF, or export TSDN_COLLECTOR_DST_MAC)" >&2
			exit 1
		fi
		eff_coll_mac="$coll_mac"
		if ! [[ "$eff_coll_mac" =~ ^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$ ]]; then
			echo "error: invalid collector MAC (expected aa:bb:cc:dd:ee:ff): $eff_coll_mac" >&2
			exit 1
		fi
	fi

	eff_switch_mac="${TSDN_SWITCH_DST_MAC:-$sw_mac}"
	if [[ -z "$eff_switch_mac" ]]; then
		echo "error: switch destination MAC missing (add \"switch_dst <aa:bb:cc:dd:ee:ff>\" to $IFACES_CONF or export TSDN_SWITCH_DST_MAC)" >&2
		exit 1
	fi
	if ! [[ "$eff_switch_mac" =~ ^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$ ]]; then
		echo "error: invalid switch_dst MAC (expected aa:bb:cc:dd:ee:ff): $eff_switch_mac" >&2
		exit 1
	fi

	cleanup_shm_ring "$P4_RULE_SHM_NAME"

	tsdn_env=(
		TSDN_LOG_RUN_DIR="$log_run"
		P4_RULE_SHM_NAME="$P4_RULE_SHM_NAME"
		TSDN_UPDATE_MODE="$TSDN_UPDATE_MODE"
		TSDN_STATS_LOG_SAMPLE_US="${TSDN_STATS_LOG_SAMPLE_US:-}"
		TSDN_COLLECTOR_INTF="$eff_coll_if"
		TSDN_COLLECTOR_SRC_MAC="${eff_coll_src_mac:-}"
		TSDN_COLLECTOR_DST_MAC="$eff_coll_mac"
		TSDN_SWITCH_DST_MAC="$eff_switch_mac"
	)

	if [[ "$with_controller" == "1" ]]; then
		if [[ ! -x "$CTRL_START" ]]; then
			echo "error: controller launcher not found or not executable: $CTRL_START" >&2
			exit 1
		fi
		echo "[$ts] starting bfrt controller (raw console output not persisted)" >&2
		stdbuf -oL -eL env TSDN_LOG_RUN_DIR="$log_run" P4_RULE_SHM_NAME="$P4_RULE_SHM_NAME" TSDN_UPDATE_MODE="$TSDN_UPDATE_MODE" "$CTRL_START" >/dev/null 2>&1 &
		echo "  controller pid $! (follow CSV with: $0 follow -c)"
		child_pids+=("$!")
	fi

	for iface in "${ifaces[@]}"; do
		echo "[$ts] starting tsdn on $iface (raw console output not persisted)" >&2
		stdbuf -oL -eL sudo env "${tsdn_env[@]}" "$BIN" "$iface" >/dev/null 2>&1 &
		echo "  pid $! → $iface (follow CSV with: $0 follow -t)"
		child_pids+=("$!")
	done

	echo ""
	echo "Run directory: $log_run (stats CSV + tsdn/*.status)"
	echo "SHM ring:      $P4_RULE_SHM_NAME"
	echo "Update mode:   $TSDN_UPDATE_MODE"
	if [[ "$with_controller" == "1" ]]; then
		echo "BFR output:    $log_run/occ*.csv"
	fi
	echo "TSDN output:   $0 follow -t → follows log/runs/latest/tsdn/*.status"
	if [[ "$with_controller" == "1" ]]; then
		echo "BFR output:    $0 follow -c → follows log/runs/latest/occ*.csv"
	fi
	echo "Live metrics:  $0 watch    → refreshes log/runs/latest/tsdn/*.status"
	echo "Stop all:       $0 stop"

	if [[ "$run_foreground" == "1" ]]; then
		local stop_timeout="${TSDN_STOP_TIMEOUT:-5}"
		trap 'echo "signal received, stopping children..."; cmd_stop "$stop_timeout"; exit 0' TERM INT QUIT
		echo ""
		echo "Foreground monitor active: waiting for controller/tsdn exits..."
		wait -n "${child_pids[@]}"
		local exited_status=$?
		echo "A child process exited (status=$exited_status); stopping remaining processes..."
		cmd_stop "$stop_timeout"
		# Non-zero exit lets systemd Restart=always relaunch everything.
		exit 1
	fi
}

cmd_start() {
	local with_controller=0
	local -a ifaces=()
	local arg
	for arg in "$@"; do
		case "$arg" in
		--with-controller | -c)
			with_controller=1
			;;
		*)
			ifaces+=("$arg")
			;;
		esac
	done
	cmd_start_common "$with_controller" 0 "${ifaces[@]}"
}

cmd_start_all() {
	cmd_start_common 1 0 "$@"
}

cmd_start_all_fg() {
	cmd_start_common 1 1 "$@"
}

cmd_stop() {
	local timeout="${1:-${TSDN_STOP_TIMEOUT:-5}}"
	if ! [[ "$timeout" =~ ^[0-9]+$ ]]; then
		echo "error: timeout_seconds must be a non-negative integer, got: $timeout" >&2
		exit 1
	fi

	# Match only this checkout's binaries/scripts to avoid killing unrelated processes.
	local -a tsdn_pids controller_pids pids
	mapfile -t tsdn_pids < <(pgrep -f "$BIN" || true)
	mapfile -t controller_pids < <(pgrep -f "$ROOT/bfrt_grpc/bfrt_controller.py" || true)

	pids=("${tsdn_pids[@]}" "${controller_pids[@]}")
	if [[ ${#pids[@]} -eq 0 ]]; then
		echo "No running process matched: $BIN or $ROOT/bfrt_grpc/bfrt_controller.py"
		return 0
	fi

	echo "Stopping this repo's processes..."
	if [[ ${#tsdn_pids[@]} -gt 0 ]]; then
		echo "  tsdn:       ${tsdn_pids[*]}"
	fi
	if [[ ${#controller_pids[@]} -gt 0 ]]; then
		echo "  controller: ${controller_pids[*]}"
	fi
	echo "Sending SIGTERM to ${#pids[@]} process(es): ${pids[*]}"
	sudo kill -TERM "${pids[@]}" 2>/dev/null || true

	local i
	for ((i = 0; i < timeout; i++)); do
		sleep 1
		mapfile -t tsdn_pids < <(pgrep -f "$BIN" || true)
		mapfile -t controller_pids < <(pgrep -f "$ROOT/bfrt_grpc/bfrt_controller.py" || true)
		pids=("${tsdn_pids[@]}" "${controller_pids[@]}")
		if [[ ${#pids[@]} -eq 0 ]]; then
			echo "All matching tsdn/controller processes exited gracefully."
			return 0
		fi
	done

	mapfile -t tsdn_pids < <(pgrep -f "$BIN" || true)
	mapfile -t controller_pids < <(pgrep -f "$ROOT/bfrt_grpc/bfrt_controller.py" || true)
	pids=("${tsdn_pids[@]}" "${controller_pids[@]}")
	if [[ ${#pids[@]} -gt 0 ]]; then
		echo "Graceful stop timed out after ${timeout}s; sending SIGKILL to: ${pids[*]}"
		sudo kill -KILL "${pids[@]}" 2>/dev/null || true
		sleep 1
	fi

	mapfile -t tsdn_pids < <(pgrep -f "$BIN" || true)
	mapfile -t controller_pids < <(pgrep -f "$ROOT/bfrt_grpc/bfrt_controller.py" || true)
	pids=("${tsdn_pids[@]}" "${controller_pids[@]}")
	if [[ ${#pids[@]} -gt 0 ]]; then
		echo "warning: still running after SIGKILL: ${pids[*]}" >&2
		return 1
	fi

	echo "All matching tsdn/controller processes stopped."
}

cmd_status() {
	if pgrep -af "$BIN" >/dev/null 2>&1; then
		pgrep -af "$BIN"
	else
		echo "No running process matched: $BIN"
	fi
	local base
	if base="$(active_tsdn_dir)"; then
		if [[ -f "$base/tsdn/interfaces.last" ]]; then
			echo ""
			echo "Last start iface list ($base/tsdn/interfaces.last):"
			cat "$base/tsdn/interfaces.last"
		fi
	fi
}

follow_controller_csv_pretty() {
	local -a files=("$@")
	local interval="${TSDN_FOLLOW_INTERVAL:-1}"
	local -a last_rows=()
	if [[ ! "$interval" =~ ^[0-9]+([.][0-9]+)?$ ]]; then
		interval=1
	fi
	while true; do
		local f
		for f in "${files[@]}"; do
			if [[ ! -f "$f" ]] || [[ "$f" != *.csv ]]; then
				continue
			fi
			local -a cycle_rows=()
			mapfile -t cycle_rows < <(awk -F',' '
				BEGIN {
					have_header = 0
				}
				function col(name,   i) {
					for (i = 1; i <= n; i++) {
						if (h[i] == name) return i
					}
					return 0
				}
				$1 == "timestamp" {
					n = split($0, h, ",")
					i_ts = col("timestamp")
					i_epoch = col("epoch")
					i_sw = col("switched")
					i_g0 = col("group0")
					i_g1 = col("group1")
					i_hot = col("hot_rules")
					i_in = col("in_s")
					i_inst = col("inst_s")
					i_del = col("del_s")
					i_pending = col("pending")
					i_hosts = col("active_hosts")
					i_rx = col("rx_pkts_s")
					i_tx = col("tx_pkts_s")
					i_depth = col("ring_depth")
					i_drop = col("ring_dropped")
					have_header = 1
					next
				}
				{
					if (!have_header) next
					printf "%-19s %5s %3s %8s %8s %8s %9s %9s %9s %9s %9s %10s %10s %8s %10s\n", \
						(i_ts ? $i_ts : "-"), (i_epoch ? $i_epoch : "-"), (i_sw ? $i_sw : "-"), \
						(i_g0 ? $i_g0 : "-"), (i_g1 ? $i_g1 : "-"), (i_hot ? $i_hot : "-"), \
						(i_in ? $i_in : "-"), (i_inst ? $i_inst : "-"), (i_del ? $i_del : "-"), \
						(i_pending ? $i_pending : "-"), (i_hosts ? $i_hosts : "-"), (i_rx ? $i_rx : "-"), (i_tx ? $i_tx : "-"), \
						(i_depth ? $i_depth : "-"), (i_drop ? $i_drop : "-")
				}
			' "$f" | tail -n 10)
			if (( ${#cycle_rows[@]} > 0 )); then
				last_rows=("${cycle_rows[@]}")
				break
			fi
		done
		printf '\033[H\033[J'
		printf "%-19s %5s %3s %8s %8s %8s %9s %9s %9s %9s %9s %10s %10s %8s %10s\n" \
			"time" "ep" "sw" "bloom_g0" "bloom_g1" "hot" "in_s" "inst_s" "del_s" "pending" "hosts" "rx_pkts/s" "tx_pkts/s" "depth" "ring_drop"
		if (( ${#last_rows[@]} == 0 )); then
			printf "%-19s %5s %3s %8s %8s %8s %9s %9s %9s %9s %9s %10s %10s %8s %10s\n" \
				"-" "-" "-" "-" "-" "-" "-" "-" "-" "-" "-" "-" "-" "-" "-"
		else
			local row
			for row in "${last_rows[@]}"; do
				printf '%s\n' "$row"
			done
		fi
		sleep "$interval"
	done
}

follow_tsdn_status_pretty() {
	local base="$1"
	local interval="${TSDN_FOLLOW_INTERVAL:-1}"
	local -a last_rows=()
	if [[ ! "$interval" =~ ^[0-9]+([.][0-9]+)?$ ]]; then
		interval=1
	fi
	while true; do
		local now
		now="$(date '+%F %T')"
		shopt -s nullglob
		local stf line iface c_if c_pkt_pps c_nic_pps c_buf c_flow c_exp c_bloom c_pcap_drp c_pcap_ifdr c_pcap_pend
		local -a cycle_rows=()
		for stf in "$base"/tsdn/*.status; do
			line="$(tr -d '\r\n' <"$stf" 2>/dev/null || true)"
			if [[ -z "$line" ]]; then
				continue
			fi
			set -- $line
			if (( $# >= 15 )); then
				read -r c_if c_pkt_pps c_nic_pps _ c_buf c_flow c_exp c_bloom _ c_pcap_drp c_pcap_ifdr c_pcap_pend _ _ _ <<<"$line"
			else
				continue
			fi
			iface="$(basename "$stf" .status)"
			cycle_rows+=("$(printf '%-19s %-10s %9s %9s %8s %9s %9s %10s %10s %10s %10s' \
				"$now" "${c_if:-$iface}" "${c_pkt_pps:--}" "${c_nic_pps:--}" "${c_buf:--}" "${c_flow:--}" "${c_exp:--}" "${c_bloom:--}" "${c_pcap_drp:--}" "${c_pcap_ifdr:--}" "${c_pcap_pend:--}")")
		done
		if [[ ${#cycle_rows[@]} -eq 0 ]]; then
			cycle_rows+=("$(printf '%-19s %-10s %9s %9s %8s %9s %9s %10s %10s %10s %10s' \
				"$now" "-" "-" "-" "-" "-" "-" "-" "-" "-" "-")")
		fi
		last_rows+=("${cycle_rows[@]}")
		if (( ${#last_rows[@]} > 10 )); then
			local start=$(( ${#last_rows[@]} - 10 ))
			last_rows=("${last_rows[@]:start:10}")
		fi
		printf '\033[H\033[J'
		printf '%-19s %-10s %9s %9s %8s %9s %9s %10s %10s %10s %10s\n' \
			"time" "iface" "pkt_pps" "nic_pps" "buf" "flow_hash" "expired" "bloom_rsp" "pcap_drop" "pcap_ifdr" "pcap_pend"
		local row
		for row in "${last_rows[@]}"; do
			printf '%s\n' "$row"
		done
		sleep "$interval"
	done
}

cmd_follow() {
	local base tsdn_dir
	local mode="tsdn"
	local arg
	for arg in "$@"; do
		case "$arg" in
		--tsdn | -t) mode="tsdn" ;;
		--controller | -c) mode="controller" ;;
		*)
			echo "error: unknown option for follow: $arg" >&2
			echo "usage: $0 follow [--tsdn|-t|--controller|-c]" >&2
			exit 1
			;;
		esac
	done
	if ! base="$(active_tsdn_dir)"; then
		echo "No log/runs/latest — run ./tsdn-multi.sh start first." >&2
		exit 1
	fi
	tsdn_dir="$base/tsdn"
	local controller_log="$base/$BFR_LOG_NAME"
	shopt -s nullglob
	local files=()
	if [[ "$mode" == "controller" ]]; then
		files=("$base"/occ*.csv)
		if [[ ${#files[@]} -eq 0 ]] && [[ -f "$controller_log" ]]; then
			files=("$controller_log")
		fi
	else
		files=("$base"/tsdn/*.status)
	fi
	if [[ ${#files[@]} -eq 0 ]]; then
		if [[ "$mode" == "controller" ]]; then
			echo "No controller output file found in $base (expected occ*.csv)" >&2
		else
			echo "No tsdn status file found in $base/tsdn (expected *.status)" >&2
		fi
		exit 1
	fi
	if [[ "$mode" == "controller" ]]; then
		if [[ ${#files[@]} -eq 1 ]] && [[ "${files[0]}" == *.csv ]]; then
			follow_controller_csv_pretty "${files[@]}"
		else
			tail -F "${files[@]}"
		fi
	else
		follow_tsdn_status_pretty "$base"
	fi
}

# Invoked by watch(1) via: watch -nN "$TSDN_MULTI_SH" _watch-render <run_dir>
# (Keeps bash arrays/shopt; avoids nested `bash -c` quoting that breaks some watch implementations.)
compact_count() {
	local n="${1:-}"
	awk -v n="$n" 'BEGIN{
		if (n !~ /^-?[0-9]+$/) { printf "%s", n; exit }
		s = ""
		if (n < 0) { s = "-"; n = -n }
		if (n >= 1e9)      printf "%s%.1fg", s, n / 1e9
		else if (n >= 1e6) printf "%s%.1fm", s, n / 1e6
		else if (n >= 1e3) printf "%s%.1fk", s, n / 1e3
		else               printf "%s%.0f", s, n
	}'
}

watch_render_status() {
	local base="$1"
	local now interval stale_sec
	if [[ -z "$base" ]] || [[ ! -d "$base/tsdn" ]]; then
		echo "error: invalid run dir: ${base:-<empty>}" >&2
		return 1
	fi
	now="$(date +%s)"
	interval="${TSDN_WATCH_INTERVAL:-1}"
	if [[ ! "$interval" =~ ^[0-9]+([.][0-9]+)?$ ]]; then
		interval=1
	fi
	stale_sec=$(( ${interval%.*} * 3 ))
	if (( stale_sec < 3 )); then
		stale_sec=3
	fi
	echo "TSDN live — $base/tsdn/*.status (see src/param.h STATS_LOG_SAMPLE_TIME)"
	printf '%-10s %8s %8s %10s %8s %8s %9s %8s %10s %8s %8s %10s %10s %10s %5s %12s\n' \
		IFACE pkt_pps nic_pps pkt buf flow exp bloom_rsp pcap_rx pcap_drp pcap_ifdr pcap_pend nic_drx nic_oob_d ruleq state
	shopt -s nullglob
	local -a ifaces=()
	local ifaces_file="$base/tsdn/interfaces.last"
	if [[ -f "$ifaces_file" ]]; then
		mapfile -t ifaces < <(awk 'NF && $1 !~ /^#/' "$ifaces_file")
	fi
	if [[ ${#ifaces[@]} -eq 0 ]]; then
		local sf
		for sf in "$base/tsdn"/*.status; do
			ifaces+=("$(basename "$sf" .status)")
		done
	fi
	if [[ ${#ifaces[@]} -eq 0 ]]; then
		echo "(no interfaces found yet)"
		return 0
	fi
	local iface stf pid age line state
	local total_line total_status_file total_log_file ts_now
	local c_if c_pkt_pps c_nic_pps c_pkt c_buf c_flow c_exp c_bloom c_pcap_rx c_pcap_drp c_pcap_ifdr c_pcap_pend c_nic_drx c_nic_oob_d c_ruleq
	local -i t_pkt_pps=0 t_pkt=0 t_buf=0 t_flow=0 t_exp=0 t_bloom=0 t_pcap_rx=0 t_pcap_drp=0 t_pcap_ifdr=0 t_pcap_pend=0 t_nic_drx=0 t_ruleq=0 t_nic_pps=0
	for iface in "${ifaces[@]}"; do
		stf="$base/tsdn/${iface}.status"
		pid="$(pgrep -f "$BIN $iface" 2>/dev/null | awk 'NR==1{print; exit}' || true)"
		if [[ -f "$stf" ]]; then
			age=$(( now - $(stat -c %Y "$stf" 2>/dev/null || echo "$now") ))
			line="$(tr -d '\r\n' <"$stf")"
			set -- $line
			if (( $# >= 15 )); then
				read -r c_if c_pkt_pps c_nic_pps c_pkt c_buf c_flow c_exp c_bloom c_pcap_rx c_pcap_drp c_pcap_ifdr c_pcap_pend c_nic_drx c_nic_oob_d c_ruleq <<<"$line"
			else
				read -r c_if c_pkt_pps c_pkt c_buf c_flow c_exp c_bloom c_pcap_rx c_pcap_drp c_pcap_ifdr c_pcap_pend c_nic_drx c_nic_oob_d c_ruleq <<<"$line"
				c_nic_pps="$c_nic_drx"
			fi
			if [[ "$c_pkt_pps" =~ ^-?[0-9]+$ ]]; then t_pkt_pps=$((t_pkt_pps + c_pkt_pps)); fi
			if [[ "$c_pkt" =~ ^-?[0-9]+$ ]]; then t_pkt=$((t_pkt + c_pkt)); fi
			if [[ "$c_buf" =~ ^-?[0-9]+$ ]]; then t_buf=$((t_buf + c_buf)); fi
			if [[ "$c_flow" =~ ^-?[0-9]+$ ]]; then t_flow=$((t_flow + c_flow)); fi
			if [[ "$c_exp" =~ ^-?[0-9]+$ ]]; then t_exp=$((t_exp + c_exp)); fi
			if [[ "$c_bloom" =~ ^-?[0-9]+$ ]]; then t_bloom=$((t_bloom + c_bloom)); fi
			if [[ "$c_pcap_rx" =~ ^-?[0-9]+$ ]]; then t_pcap_rx=$((t_pcap_rx + c_pcap_rx)); fi
			if [[ "$c_pcap_drp" =~ ^-?[0-9]+$ ]]; then t_pcap_drp=$((t_pcap_drp + c_pcap_drp)); fi
			if [[ "$c_pcap_ifdr" =~ ^-?[0-9]+$ ]]; then t_pcap_ifdr=$((t_pcap_ifdr + c_pcap_ifdr)); fi
			if [[ "$c_pcap_pend" =~ ^-?[0-9]+$ ]]; then t_pcap_pend=$((t_pcap_pend + c_pcap_pend)); fi
			if [[ "$c_nic_drx" =~ ^-?[0-9]+$ ]]; then t_nic_drx=$((t_nic_drx + c_nic_drx)); fi
			if [[ "$c_nic_pps" =~ ^-?[0-9]+$ ]]; then t_nic_pps=$((t_nic_pps + c_nic_pps)); fi
			if [[ "$c_ruleq" =~ ^-?[0-9]+$ ]]; then t_ruleq=$((t_ruleq + c_ruleq)); fi
			c_pkt="$(compact_count "$c_pkt")"
			c_buf="$(compact_count "$c_buf")"
			c_flow="$(compact_count "$c_flow")"
			c_exp="$(compact_count "$c_exp")"
			c_pcap_rx="$(compact_count "$c_pcap_rx")"
			c_nic_pps="$(compact_count "$c_nic_pps")"
			if (( age > stale_sec )); then
				state="STALE(${age}s)"
			else
				state="OK"
			fi
			printf '%-10s %8s %8s %10s %8s %8s %9s %8s %10s %8s %8s %10s %10s %10s %5s %12s\n' \
				"$c_if" "$c_pkt_pps" "$c_nic_pps" "$c_pkt" "$c_buf" "$c_flow" "$c_exp" "$c_bloom" \
				"$c_pcap_rx" "$c_pcap_drp" "$c_pcap_ifdr" "$c_pcap_pend" "$c_nic_drx" \
				"$c_nic_oob_d" "$c_ruleq" "$state"
		else
			if [[ -n "$pid" ]]; then
				printf '!! %-8s NO_STATUS pid=%-8s %12s\n' "$iface" "$pid" "NO_STATUS"
			else
				printf '!! %-8s pid=%-8s %12s\n' "$iface" "-" "CRASHED"
			fi
		fi
	done
	total_line="$(printf '%-10s %8s %8s %10s %8s %8s %9s %8s %10s %8s %8s %10s %10s %10s %5s %12s' \
		"TOTAL" \
		"$(compact_count "$t_pkt_pps")" \
		"$(compact_count "$t_nic_pps")" \
		"$(compact_count "$t_pkt")" \
		"$(compact_count "$t_buf")" \
		"$(compact_count "$t_flow")" \
		"$(compact_count "$t_exp")" \
		"$(compact_count "$t_bloom")" \
		"$(compact_count "$t_pcap_rx")" \
		"$(compact_count "$t_pcap_drp")" \
		"$(compact_count "$t_pcap_ifdr")" \
		"$(compact_count "$t_pcap_pend")" \
		"$(compact_count "$t_nic_drx")" \
		"-" \
		"$(compact_count "$t_ruleq")" \
		"SUM")"
	echo "$total_line"

	total_status_file="$base/tsdn/total.status"
	total_log_file="$base/tsdn/total.log"
	printf '%s\n' "$total_line" >"$total_status_file"
	ts_now="$(date -Iseconds)"
	printf '[%s] %s\n' "$ts_now" "$total_line" >>"$total_log_file"
}

cmd_watch() {
	local base interval="${TSDN_WATCH_INTERVAL:-1}"
	if ! base="$(active_tsdn_dir)"; then
		echo "No log/runs/latest — run ./tsdn-multi.sh start first." >&2
		exit 1
	fi
	if ! command -v watch >/dev/null 2>&1; then
		echo "error: watch(1) not found; install procps or use: tail -F $base/tsdn/*.status" >&2
		exit 1
	fi
	exec watch -n"$interval" "$TSDN_MULTI_SH" _watch-render "$base"
}

main() {
	local cmd="${1:-}"
	shift || true

	case "$cmd" in
	start) cmd_start "$@" ;;
	start-all) cmd_start_all "$@" ;;
	start-all-fg) cmd_start_all_fg "$@" ;;
	list) cmd_list "$@" ;;
	stop) cmd_stop "$@" ;;
	status) cmd_status ;;
	follow | tail) cmd_follow "$@" ;;
	_watch-render)
		watch_render_status "${1:-}"
		exit $?
		;;
	watch | top) cmd_watch ;;
	"" | -h | --help | help) usage ;;
	*)
		echo "unknown command: $cmd" >&2
		usage >&2
		exit 1
		;;
	esac
}

main "$@"
