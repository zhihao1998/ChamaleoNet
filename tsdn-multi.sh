#!/usr/bin/env bash
# Multi-interface launcher for tsdn: one `make`, N processes.
# Each `start` creates log/runs/<YYYYMMDD_HH-MM-SS>/ with stats CSVs and tsdn/<iface>.log;
# log/runs/latest → that run (for follow / status).
#
# Commands (see also ./tsdn-multi.sh --help):
#   start [iface ...]   With no args: read conf/tsdn.interfaces (or TSDN_INTERFACES_FILE).
#   list                Print the interface list that a no-arg start would use.
#   follow | tail       tail -F all per-iface logs (Ctrl+C stops tail, not tsdn).
#   watch | top         Dynamic refresh of per-iface *.status (same data as stderr lines).
#   stop | status       Kill or show processes for this repo's bin/tsdn only.
#
# Environment (optional):
#   TSDN_INTERFACES_FILE  Path to iface list (default: conf/tsdn.interfaces in repo root).
#   TSDN_MAKE_CLEAN=1      Run make clean && make once before start.
#   TSDN_SKIP_MAKE=1       Do not run make before start.
#   TSDN_SKIP_IFUP=1       Skip "sudo ifconfig <iface> up" before each instance.
#   TSDN_WATCH_INTERVAL    Seconds between watch refreshes (default 1).

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TSDN_MULTI_SH="$(readlink -f "${BASH_SOURCE[0]}")"
BIN="$ROOT/bin/tsdn"
RUNS_ROOT="$ROOT/log/runs"
LATEST_RUN_LINK="$RUNS_ROOT/latest"
IFACES_CONF="${TSDN_INTERFACES_FILE:-$ROOT/conf/tsdn.interfaces}"

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

Each successful start creates: log/runs/<YYYYMMDD_HH-MM-SS>/{*.csv, tsdn/<iface>.log}
Symlink log/runs/latest points at the last start (used by follow / status iface list).

Commands:
  start [iface ...]           no args: read $IFACES_CONF (default conf/tsdn.interfaces)
  list                        print interface list from config (same as bare start)
  stop [timeout_seconds]      TERM then KILL this repo's bin/tsdn (default timeout: 5s)
  status                      show matching processes
  follow | tail               tail -F all *.log under log/runs/latest/tsdn/
  watch | top                 watch(1) refresh of log/runs/latest/tsdn/*.status

Env: TSDN_INTERFACES_FILE=path   → default iface list file for "start" / "list"
     TSDN_MAKE_CLEAN=1  → make clean && make
     TSDN_SKIP_MAKE=1   → skip make before start
     TSDN_SKIP_IFUP=1   → skip ifconfig up before start
     TSDN_WATCH_INTERVAL=seconds → interval for watch (default 1)
EOF
}

# Parse conf: skip blank / comment lines; support multiple ifaces per line.
read_ifaces_from_config() {
	local f="$1"
	if [[ ! -f "$f" ]]; then
		echo "error: interface list not found: $f" >&2
		echo "  cp $ROOT/conf/tsdn.interfaces.example $f" >&2
		echo "  edit $f, then: $0 start" >&2
		exit 1
	fi
	awk '!/^[[:space:]]*(#|$)/ && NF { for (i = 1; i <= NF; i++) print $i }' "$f"
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

cmd_start() {
	local -a ifaces
	mapfile -t ifaces < <(resolve_start_ifaces "$@")

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
		printf '%s\n' "${ifaces[@]}"
	} >"$tsdn_dir/README-interfaces.txt"

	bring_interfaces_up "${ifaces[@]}"

	for iface in "${ifaces[@]}"; do
		local logf="$tsdn_dir/${iface}.log"
		echo "[$ts] starting tsdn on $iface (log: $logf)" | tee -a "$logf"
		# sudo drops env by default — pass TSDN_LOG_RUN_DIR explicitly.
		stdbuf -oL -eL sudo env TSDN_LOG_RUN_DIR="$log_run" "$BIN" "$iface" >>"$logf" 2>&1 &
		echo "  pid $! → $iface"
	done

	echo ""
	echo "Run directory: $log_run (stats CSV + tsdn/*.log)"
	echo "Watch output:  $0 follow   → tails log/runs/latest/tsdn/*.log"
	echo "Live metrics:  $0 watch    → refreshes log/runs/latest/tsdn/*.status"
	echo "Stop all:       $0 stop"
}

cmd_stop() {
	local timeout="${1:-${TSDN_STOP_TIMEOUT:-5}}"
	if ! [[ "$timeout" =~ ^[0-9]+$ ]]; then
		echo "error: timeout_seconds must be a non-negative integer, got: $timeout" >&2
		exit 1
	fi

	# Match only this checkout's binary path to avoid killing unrelated tsdn.
	local -a pids
	mapfile -t pids < <(pgrep -f "$BIN" || true)
	if [[ ${#pids[@]} -eq 0 ]]; then
		echo "No running process matched: $BIN"
		return 0
	fi

	echo "Stopping: $BIN"
	echo "Sending SIGTERM to ${#pids[@]} process(es): ${pids[*]}"
	sudo kill -TERM "${pids[@]}" 2>/dev/null || true

	local i
	for ((i = 0; i < timeout; i++)); do
		sleep 1
		mapfile -t pids < <(pgrep -f "$BIN" || true)
		if [[ ${#pids[@]} -eq 0 ]]; then
			echo "All matching tsdn processes exited gracefully."
			return 0
		fi
	done

	mapfile -t pids < <(pgrep -f "$BIN" || true)
	if [[ ${#pids[@]} -gt 0 ]]; then
		echo "Graceful stop timed out after ${timeout}s; sending SIGKILL to: ${pids[*]}"
		sudo kill -KILL "${pids[@]}" 2>/dev/null || true
		sleep 1
	fi

	mapfile -t pids < <(pgrep -f "$BIN" || true)
	if [[ ${#pids[@]} -gt 0 ]]; then
		echo "warning: still running after SIGKILL: ${pids[*]}" >&2
		return 1
	fi

	echo "All matching tsdn processes stopped."
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

cmd_follow() {
	local base tsdn_dir
	if ! base="$(active_tsdn_dir)"; then
		echo "No log/runs/latest — run ./tsdn-multi.sh start first." >&2
		exit 1
	fi
	tsdn_dir="$base/tsdn"
	shopt -s nullglob
	local files=("$tsdn_dir"/*.log)
	if [[ ${#files[@]} -eq 0 ]]; then
		echo "No *.log in $tsdn_dir" >&2
		exit 1
	fi
	tail -F "${files[@]}"
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
	printf '%-10s %8s %8s %10s %8s %8s %9s %8s %10s %8s %8s %10s %10s %10s %5s %10s %12s\n' \
		IFACE pkt_pps nic_pps pkt buf flow exp bloom_rsp pcap_rx pcap_drp pcap_ifdr pcap_pend nic_drx nic_oob_d ruleq app_drop state
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
	local iface stf logf pid age lastlog line app_drop state
	local total_line total_status_file total_log_file ts_now
	local c_if c_pkt_pps c_nic_pps c_pkt c_buf c_flow c_exp c_bloom c_pcap_rx c_pcap_drp c_pcap_ifdr c_pcap_pend c_nic_drx c_nic_oob_d c_ruleq
	local -i t_pkt_pps=0 t_pkt=0 t_buf=0 t_flow=0 t_exp=0 t_bloom=0 t_pcap_rx=0 t_pcap_drp=0 t_pcap_ifdr=0 t_pcap_pend=0 t_nic_drx=0 t_ruleq=0 t_app_drop=0 t_nic_pps=0
	for iface in "${ifaces[@]}"; do
		stf="$base/tsdn/${iface}.status"
		logf="$base/tsdn/${iface}.log"
		pid="$(pgrep -f "$BIN $iface" 2>/dev/null | awk 'NR==1{print; exit}' || true)"
		app_drop="$(awk 'match($0,/pkt buffer overflow: drop packet \(count=([0-9]+)\)/,m){c=m[1]} END{if(c=="") c=0; print c}' "$logf" 2>/dev/null || echo 0)"
		if [[ "$app_drop" =~ ^-?[0-9]+$ ]]; then
			t_app_drop=$((t_app_drop + app_drop))
		fi
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
			printf '%-10s %8s %8s %10s %8s %8s %9s %8s %10s %8s %8s %10s %10s %10s %5s %10s %12s\n' \
				"$c_if" "$c_pkt_pps" "$c_nic_pps" "$c_pkt" "$c_buf" "$c_flow" "$c_exp" "$c_bloom" \
				"$c_pcap_rx" "$c_pcap_drp" "$c_pcap_ifdr" "$c_pcap_pend" "$c_nic_drx" \
				"$c_nic_oob_d" "$c_ruleq" "$app_drop" "$state"
		else
			lastlog="$(awk 'NF{last=$0} END{print last}' "$logf" 2>/dev/null)"
			if [[ -n "$pid" ]]; then
				printf '!! %-8s NO_STATUS pid=%-8s app_drop=%-10s %12s\n' "$iface" "$pid" "$app_drop" "NO_STATUS"
			elif [[ -n "$lastlog" ]]; then
				printf '!! %-8s pid=%-8s app_drop=%-10s %12s | %s\n' "$iface" "-" "$app_drop" "CRASHED" "$lastlog"
			else
				printf '!! %-8s pid=%-8s app_drop=%-10s %12s\n' "$iface" "-" "$app_drop" "CRASHED"
			fi
		fi
	done
	total_line="$(printf '%-10s %8s %8s %10s %8s %8s %9s %8s %10s %8s %8s %10s %10s %10s %5s %10s %12s' \
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
		"$(compact_count "$t_app_drop")" \
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
	list) cmd_list "$@" ;;
	stop) cmd_stop "$@" ;;
	status) cmd_status ;;
	follow | tail) cmd_follow ;;
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
