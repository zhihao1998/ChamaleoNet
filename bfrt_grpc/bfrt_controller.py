#!/usr/bin/python3
"""
Combined BFRT controller: bloom epoch rotation + UDX rule install + idle cleanup + active host tracking.
UDX receives on a dedicated thread; BFRT/gRPC runs on the main thread (gRPC is not thread-safe).
"""
import binascii
import csv
import os
import selectors
import socket
import struct
import sys
import threading
import time
import queue
import mmap
import itertools
from datetime import datetime

# =========================
# P4 userspace datagram protocol (rule push)
# =========================
P4_MAGIC = 0x5034
P4_VER = 1
P4_OP_INSTALL = 1

HDR = struct.Struct("!HBBHH")
RULE = struct.Struct("!BBHI")
HDR_SIZE = HDR.size
RULE_SIZE = RULE.size

SHM_RING_MAGIC = 0x31515250
SHM_RING_VERSION = 1
SHM_RING_HDR_SIZE = 64
SHM_OFF_MAGIC = 0
SHM_OFF_VERSION = 4
SHM_OFF_CAP = 8
SHM_OFF_HEAD = 16
SHM_OFF_TAIL = 20
SHM_OFF_DROPPED = 28
SHM_OFF_PUSHES = 32
SHM_OFF_POPS = 40
DEFAULT_SHM_NAME = "/p4_rule_ring"

SHM_HDR_U32 = struct.Struct("<I")
SHM_HDR_U64 = struct.Struct("<Q")

# =========================
# Statistics
# =========================
stats = {
    "pkts_ok": 0,
    "pkts_bad": 0,
    "pkts_trunc": 0,
    "sock_drop": 0,
    "rules_in": 0,
    "rules_pending_add": 0,
    "rules_installed": 0,
    "rules_deleted": 0,
    "batches_ok": 0,
    "batches_fail": 0,
    "adds_fail": 0,
}
stats_lock = threading.Lock()
data_lock = threading.Lock()  # protects rule_epoch_seen, active_hosts, epoch_counter_ref
# =========================
# Controller dependencies (Tofino BFRT)
# =========================
SDE_INSTALL = os.environ["SDE_INSTALL"]
PYTHON3_VER = "{}.{}".format(sys.version_info.major, sys.version_info.minor)
SDE_PYTHON3 = os.path.join(SDE_INSTALL, "lib", "python" + PYTHON3_VER, "site-packages")

sys.path.append(SDE_PYTHON3)
sys.path.append(os.path.join(SDE_PYTHON3, "tofino"))
sys.path.append(os.path.join(SDE_PYTHON3, "tofino", "bfrt_grpc"))

import bfrt_grpc.bfruntime_pb2 as bfruntime_pb2
import bfrt_grpc.client as gc

remote_grpc_addr = "192.168.24.69:50052"


def ip_to_int(ipv4_address: str) -> int:
    return struct.unpack("!I", socket.inet_aton(ipv4_address))[0]


def int_to_ip(ip_int: int) -> str:
    return socket.inet_ntoa(struct.pack("!I", ip_int & 0xFFFFFFFF))


def mask_to_int(mask: str) -> int:
    return int(binascii.hexlify(socket.inet_aton(mask)), 16)


def mac_to_bytes(mac_str: str) -> bytes:
    return bytes.fromhex(mac_str.replace(":", ""))


def flow_key(ip_int: int, port: int, proto: int) -> int:
    return ((ip_int & 0xFFFFFFFF) << 24) | ((port & 0xFFFF) << 8) | (proto & 0xFF)


def unpack_flow_key(k: int):
    proto = k & 0xFF
    port = (k >> 8) & 0xFFFF
    ip_int = (k >> 24) & 0xFFFFFFFF
    return ip_int, port, proto


def fmt_num(value) -> str:
    """Format numbers for readable console output."""
    if isinstance(value, float):
        return f"{int(round(value)):,}"
    return f"{value:,}"


def build_status_report(
    now_dt: datetime,
    current_epoch: int,
    did_epoch_switch: bool,
    epoch_delay_ms: float,
    v0: int,
    v1: int,
    rin: float,
    rpend: float,
    rinst: float,
    rdel: float,
    pending_delta_s: float,
    add_fail_s: float,
    install_batch: int,
    pend_sz: int,
    fail_sz: int,
    hot_sz: int,
    local_num: int,
    usage: int,
    active_num: int,
    s: dict,
    rx_pkts_s: float,
    tx_pkts_s: float,
    ring_depth: int,
    ring_pushes: int,
    ring_pops: int,
    ring_dropped: int,
) -> str:
    """Build a grouped, human-readable status report."""
    switched_mark = "yes" if did_epoch_switch else "no"
    label_w = 11
    value_w = 14

    def cell(label: str, value) -> str:
        return f"{label:<{label_w}} {fmt_num(value):>{value_w}}"

    def row(group: str, items) -> str:
        cols = " | ".join(cell(label, value) for label, value in items)
        return f"{group:<5} | {cols}"

    divider = "-" * 120
    return "\n".join(
        [
            divider,
            f"[{now_dt.strftime('%H:%M:%S')}] epoch={current_epoch:<2} switched={switched_mark} epoch_delay_ms={fmt_num(epoch_delay_ms)}",
            row("rate", [("in/s", rin), ("pend_add/s", rpend), ("inst/s", rinst), ("del/s", rdel), ("pend_delta/s", pending_delta_s)]),
            row("queue", [("pending", pend_sz), ("fail_cd", fail_sz), ("hot_rules", hot_sz), ("batch_sz", install_batch)]),
            row("perf", [("add_fail/s", add_fail_s)]),
            row("table", [("local", local_num), ("usage", usage), ("active_hosts", active_num)]),
            row("bloom", [("g0", v0), ("g1", v1)]),
            row("pkt", [("ok", s["pkts_ok"]), ("bad", s["pkts_bad"]), ("trunc", s["pkts_trunc"]), ("sock_drop", s["sock_drop"])]),
            row("batch", [("ok", s["batches_ok"]), ("fail", s["batches_fail"]), ("rx_pkts/s", rx_pkts_s), ("tx_pkts/s", tx_pkts_s)]),
            row("ring", [("depth", ring_depth), ("pushes", ring_pushes), ("pops", ring_pops), ("dropped", ring_dropped)]),
            divider,
        ]
    )


# =========================
# Global: pending rules, failure cooldown, active host state
# pending_queue: UDX thread writes, main thread reads; pending_set/failed_until on main thread
# active_hosts/rule_epoch_seen require data_lock
# =========================
pending_set = set()
pending_queue = queue.SimpleQueue()
failed_until = {}
FAILED_COOLDOWN_SEC = 0.2
FAILED_MAX_SIZE = 200000

# Host is active if UDX sent rules or hardware still has non-expired entries
# active_hosts: ip_int -> {"flow_count": int, "last_udx": float}
active_hosts = {}
UDX_ACTIVE_SEC = 60.0  # seconds UDX activity window after last rule seen

# Only enqueue rules after consecutive epoch hits:
# rule_epoch_seen: flow_key -> (last_seen_epoch, streak_len, last_queued_epoch)
# consecutive window length is HOT_WINDOW_EPOCHS (default 2).
rule_epoch_seen = {}
HOT_WINDOW_EPOCHS = 2

# Performance tuning (high load ~65k flows)
MAX_IDLE_PER_LOOP = 80   # max idle notifications per loop (avoid long main-loop stalls)
MAX_PUSH_PER_LOOP = 8192  # max rules installed per loop (throughput first)
ACTIVE_CLEAN_INTERVAL = 5.0  # active_hosts cleanup interval (seconds), eases ~65k-scale scans
# Prefer on-time bloom clears/usage reads; may defer some installs
RULE_INSTALL_BUDGET_SEC = 0.8   # per-loop time budget for installs (smoother progress)
EPOCH_SWITCH_MARGIN_SEC = 0.05  # stop installs this long before next bloom flip
REFRESH_HOT_MAX_SEC = 0.35      # max CPU time per refresh_hot_rules call
PENDING_CAP_FOR_BLOOM = 200000  # higher pending cap to drop fewer rules under load
MAX_ENQUEUE_DRAIN_PER_LOOP = 50000  # max items moved pending_queue -> pending_set per loop
hot_rules_count = [0]  # cache updated by refresh_hot_rules
IDLE_CLEAN_INTERVAL_SEC = 0.2
IDLE_CLEAN_SKIP_PENDING = 4096
DEFAULT_IDLE_CLEAN_TARGET_PER_SEC = 320.0
DEFAULT_IDLE_CLEAN_BURST = float(MAX_IDLE_PER_LOOP * 8)
DEFAULT_IDLE_CLEAN_MAX_CALLS_PER_LOOP = 4
DEFAULT_IDLE_CLEAN_POLL_TIMEOUT_SEC = 0.002

INCOMING_PORT = 140
OUTGOING_PORT = 140


def reset_runtime_queues():
    """Clear local queues and caches before each startup."""
    global pending_queue
    pending_set.clear()
    failed_until.clear()
    rule_epoch_seen.clear()
    pending_queue = queue.SimpleQueue()
    with data_lock:
        active_hosts.clear()

def parse_datagram_to_keys(data: bytes):
    """Returns list[int] (packed keys) on success, else None. Updates stats under stats_lock."""
    mv = memoryview(data)
    if len(mv) < HDR_SIZE:
        with stats_lock:
            stats["pkts_bad"] += 1
        return None

    magic, ver, op, count, _ = HDR.unpack_from(mv, 0)
    if magic != P4_MAGIC or ver != P4_VER or op != P4_OP_INSTALL:
        with stats_lock:
            stats["pkts_bad"] += 1
        return None

    expected = HDR_SIZE + count * RULE_SIZE
    if len(mv) != expected:
        with stats_lock:
            stats["pkts_trunc"] += 1
        return None

    keys = []
    off = HDR_SIZE
    for _ in range(count):
        proto, _r, port, ipv4_int = RULE.unpack_from(mv, off)
        keys.append(flow_key(ipv4_int, port, proto))
        off += RULE_SIZE

    with stats_lock:
        stats["pkts_ok"] += 1
        stats["rules_in"] += len(keys)
    return keys


class ShmRuleRingReader:
    """Read rules from POSIX SHM ring produced by C workers."""

    def __init__(self, shm_name: str):
        if not shm_name.startswith("/"):
            raise ValueError("shm_name must start with '/'")
        shm_path = f"/dev/shm/{shm_name[1:]}"
        self.fd = os.open(shm_path, os.O_RDWR)
        size = os.fstat(self.fd).st_size
        if size < SHM_RING_HDR_SIZE:
            raise RuntimeError("shared ring is too small")
        self.mm = mmap.mmap(self.fd, size)
        self.capacity = SHM_HDR_U32.unpack_from(self.mm, SHM_OFF_CAP)[0]
        magic = SHM_HDR_U32.unpack_from(self.mm, SHM_OFF_MAGIC)[0]
        version = SHM_HDR_U32.unpack_from(self.mm, SHM_OFF_VERSION)[0]
        if magic != SHM_RING_MAGIC or version != SHM_RING_VERSION:
            raise RuntimeError("shared ring magic/version mismatch")
        self.slot_base = SHM_RING_HDR_SIZE
        self.slot_size = RULE_SIZE

    def close(self):
        self.mm.close()
        os.close(self.fd)

    def drain(self, max_items: int = 50000):
        keys = []
        cap = self.capacity
        head = SHM_HDR_U32.unpack_from(self.mm, SHM_OFF_HEAD)[0]
        tail = SHM_HDR_U32.unpack_from(self.mm, SHM_OFF_TAIL)[0]
        while head != tail and len(keys) < max_items:
            off = self.slot_base + head * self.slot_size
            proto, _, port, ipv4_int = RULE.unpack_from(self.mm, off)
            keys.append(flow_key(ipv4_int, port, proto))
            head = (head + 1) % cap
        if keys:
            SHM_HDR_U32.pack_into(self.mm, SHM_OFF_HEAD, head)
            pops = SHM_HDR_U64.unpack_from(self.mm, SHM_OFF_POPS)[0]
            SHM_HDR_U64.pack_into(self.mm, SHM_OFF_POPS, pops + len(keys))
        return keys

    def snapshot(self):
        head = SHM_HDR_U32.unpack_from(self.mm, SHM_OFF_HEAD)[0]
        tail = SHM_HDR_U32.unpack_from(self.mm, SHM_OFF_TAIL)[0]
        depth = (tail + self.capacity - head) % self.capacity
        return {
            "depth": depth,
            "pushes": SHM_HDR_U64.unpack_from(self.mm, SHM_OFF_PUSHES)[0],
            "pops": SHM_HDR_U64.unpack_from(self.mm, SHM_OFF_POPS)[0],
            "dropped": SHM_HDR_U32.unpack_from(self.mm, SHM_OFF_DROPPED)[0],
        }

    def clear(self):
        """Drop backlog in SHM ring so the controller starts with an empty queue."""
        head = SHM_HDR_U32.unpack_from(self.mm, SHM_OFF_HEAD)[0]
        tail = SHM_HDR_U32.unpack_from(self.mm, SHM_OFF_TAIL)[0]
        depth = (tail + self.capacity - head) % self.capacity
        if depth:
            SHM_HDR_U32.pack_into(self.mm, SHM_OFF_HEAD, tail)
            pops = SHM_HDR_U64.unpack_from(self.mm, SHM_OFF_POPS)[0]
            SHM_HDR_U64.pack_into(self.mm, SHM_OFF_POPS, pops + depth)


class Bfrt_GRPC_Client:
    """Combined: bloom epoch + active_host_tbl install/idle delete + active host tracking."""

    REGISTER_TABLES = {
        0: ("Ingress.bloom_group0_epoch0", "Ingress.bloom_group1_epoch0"),
        1: ("Ingress.bloom_group0_epoch1", "Ingress.bloom_group1_epoch1"),
    }
    COUNTER_TABLES = {
        0: ("Ingress.bloom_counter_group0_epoch_0", "Ingress.bloom_counter_group1_epoch_0"),
        1: ("Ingress.bloom_counter_group0_epoch_1", "Ingress.bloom_counter_group1_epoch_1"),
    }

    def __init__(
        self,
        entry_ttl=5000,
        clean_batch_size=1000,
        grpc_addr=remote_grpc_addr,
        client_id=0,
        p4_name=None,
        perform_bind=True,
        timeout=1,
        num_tries=5,
        perform_subscribe=True,
        target=gc.Target(),
    ):
        if perform_bind and not perform_subscribe:
            raise RuntimeError("perform_bind must be equal to perform_subscribe")

        self.bfrt_info = None
        self.target = target
        self.installed_flows = set()

        self.interface = gc.ClientInterface(
            grpc_addr,
            client_id=client_id,
            device_id=0,
            notifications=gc.Notifications(
                enable_idletimeout=True,
                enable_entry_active=False,
                enable_port_status_change=False,
                enable_learn=False,
            ),
            timeout=timeout,
            num_tries=num_tries,
            perform_subscribe=perform_subscribe,
        )

        if not p4_name:
            self.bfrt_info = self.interface.bfrt_info_get()
            self.p4_name = self.bfrt_info.p4_name_get()

        if perform_bind:
            self.interface.bind_pipeline_config(self.p4_name)

        self.service_table = self.bfrt_info.table_get("pipe.Ingress.active_host_tbl")
        self.service_table.info.key_field_annotation_add("meta.internal_ip", "ipv4")
        self.service_table.attribute_idle_time_set(
            self.target,
            True,
            bfruntime_pb2.IdleTable.IDLE_TABLE_NOTIFY_MODE,
            entry_ttl,
        )

        self.entry_ttl = entry_ttl
        self.clean_batch_size = clean_batch_size

    def __getattr__(self, name):
        return getattr(self.interface, name)

    def clear_table(self, table_name: str):
        """Clear a table (register or counter)."""
        t = self.bfrt_info.table_get(table_name)
        try:
            t.entry_del(self.target, [])
        except Exception:
            pass
        table_type = t.info.type_get()
        if "MatchAction" in table_type:
            try:
                t.default_entry_reset(self.target)
            except Exception:
                pass

    def get_counter_value(self, counter_name: str) -> int:
        """Return counter $COUNTER_SPEC_PKTS value."""
        counter = self.bfrt_info.table_get(counter_name)
        data, _ = next(
            counter.entry_get(
                self.target, [counter.make_key([gc.KeyTuple("$COUNTER_INDEX", 0)])]
            )
        )
        return data.to_dict().get("$COUNTER_SPEC_PKTS", 0)

    def set_bloom_epoch(self, epoch: int):
        bloom_epoch_table = self.bfrt_info.table_get("Ingress.bloom_epoch_tbl")
        bloom_epoch_table.entry_mod(
            self.target,
            [
                bloom_epoch_table.make_key(
                    [gc.KeyTuple("meta.bloom_dummy_key", 0)]
                )
            ],
            [
                bloom_epoch_table.make_data(
                    [gc.DataTuple("epoch", epoch)], "set_epoch"
                )
            ],
        )

    def clear_service_table(self):
        self.service_table.entry_del(self.target, [])
        self.installed_flows.clear()
        with data_lock:
            active_hosts.clear()
        # clear all registers and counters
        for e in (0, 1):
            for t in self.REGISTER_TABLES[e]:
                self.clear_table(t)
            for t in self.COUNTER_TABLES[e]:
                self.clear_table(t)

    def get_table_usage(self) -> int:
        return int(
            next(self.service_table.usage_get(self.target, flags={"from_hw": False}))
        )

    def get_local_flow_entry_num(self) -> int:
        return len(self.installed_flows)

    def get_active_host_count(self) -> int:
        """Active hosts: flow_count>0 or last_udx within UDX_ACTIVE_SEC."""
        now = time.monotonic()
        with data_lock:
            return sum(
                1
                for v in active_hosts.values()
                if v["flow_count"] > 0
                or (v["last_udx"] is not None and now - v["last_udx"] < UDX_ACTIVE_SEC)
            )

    def idle_entry_batch_clean(self, timeout=0.01, max_fetch=MAX_IDLE_PER_LOOP):
        """Poll idle notifications from gRPC and batch-delete entries. max_fetch caps work per loop."""
        key_list = []
        removed_keys = []

        while len(key_list) < min(self.clean_batch_size, max_fetch):
            try:
                idle_notification = self.interface.idletime_notification_get(
                    timeout=timeout
                )
                recv_key = self.bfrt_info.key_from_idletime_notification(
                    idle_notification
                )
                key_dict = recv_key.to_dict()

                ip = key_dict["meta.internal_ip"]["value"]
                port = key_dict["meta.internal_port"]["value"]
                proto = key_dict["meta.ip_protocol"]["value"]

                k = flow_key(ip_to_int(ip), port, proto)
                removed_keys.append(k)
                key_list.append(recv_key)

            except RuntimeError:
                break
            except KeyError:
                pass

        if key_list:
            try:
                self.service_table.entry_del(self.target, key_list)
            except Exception:
                return 0

            for k in removed_keys:
                self.installed_flows.discard(k)
            with data_lock:
                for k in removed_keys:
                    ip_int = unpack_flow_key(k)[0]
                    if ip_int in active_hosts:
                        active_hosts[ip_int]["flow_count"] -= 1
                        if active_hosts[ip_int]["flow_count"] <= 0:
                            active_hosts[ip_int]["flow_count"] = 0
            for k in removed_keys:
                failed_until.pop(k, None)
            with stats_lock:
                stats["rules_deleted"] += len(removed_keys)

        return len(removed_keys)

    def entry_add_batch(self, keys_batch: list, strict_batch: bool = True):
        """Batch-install rules and update installed_flows / active_hosts.

        If strict_batch=True, batch failure skips per-entry fallback (throughput-first, like baseline).
        """
        keys_batch = [k for k in keys_batch if k not in self.installed_flows]
        if not keys_batch:
            return

        key_list = []
        ip_ints = []
        entry_triples = []
        ip_cache = {}
        for k in keys_batch:
            ip_int, port, proto = unpack_flow_key(k)
            ip_ints.append(ip_int)
            entry_triples.append((ip_int, port, proto))
            ip_str = ip_cache.get(ip_int)
            if ip_str is None:
                ip_str = int_to_ip(ip_int)
                ip_cache[ip_int] = ip_str
            service_keys = self.service_table.make_key(
                [
                    gc.KeyTuple("meta.internal_ip", ip_str),
                    gc.KeyTuple("meta.internal_port", port),
                    gc.KeyTuple("meta.ip_protocol", proto),
                ]
            )
            key_list.append(service_keys)

        # All installed rules share the same action/TTL payload.
        shared_data = self.service_table.make_data(
            [gc.DataTuple("$ENTRY_TTL", self.entry_ttl)],
            "Ingress.drop",
        )
        data_list = [shared_data] * len(key_list)

        try:
            self.service_table.entry_add(self.target, key_list, data_list)
            for k in keys_batch:
                self.installed_flows.add(k)
            ip_increments = {}
            for ip_int in ip_ints:
                ip_increments[ip_int] = ip_increments.get(ip_int, 0) + 1
            with data_lock:
                for ip_int, inc in ip_increments.items():
                    if ip_int not in active_hosts:
                        active_hosts[ip_int] = {"flow_count": 0, "last_udx": None}
                    active_hosts[ip_int]["flow_count"] += inc
            with stats_lock:
                stats["batches_ok"] += 1
                stats["rules_installed"] += len(keys_batch)
            return
        except Exception:
            with stats_lock:
                stats["batches_fail"] += 1

        if strict_batch:
            now = time.monotonic()
            for k in keys_batch:
                if len(failed_until) > FAILED_MAX_SIZE:
                    for kk in list(failed_until.keys())[: len(failed_until) // 2]:
                        failed_until.pop(kk, None)
                failed_until[k] = now + FAILED_COOLDOWN_SEC
            with stats_lock:
                stats["adds_fail"] += len(keys_batch)
            return

        now = time.monotonic()
        ok_count = 0
        for k, (ip_int, port, proto) in zip(keys_batch, entry_triples):
            try:
                one_key = self.service_table.make_key(
                    [
                        gc.KeyTuple("meta.internal_ip", ip_cache[ip_int]),
                        gc.KeyTuple("meta.internal_port", port),
                        gc.KeyTuple("meta.ip_protocol", proto),
                    ]
                )
                one_data = self.service_table.make_data(
                    [gc.DataTuple("$ENTRY_TTL", self.entry_ttl)],
                    "Ingress.drop",
                )
                self.service_table.entry_add(self.target, [one_key], [one_data])

                self.installed_flows.add(k)
                with data_lock:
                    if ip_int not in active_hosts:
                        active_hosts[ip_int] = {"flow_count": 0, "last_udx": None}
                    active_hosts[ip_int]["flow_count"] += 1
                ok_count += 1

            except Exception:
                if len(failed_until) > FAILED_MAX_SIZE:
                    for kk in list(failed_until.keys())[: len(failed_until) // 2]:
                        failed_until.pop(kk, None)
                failed_until[k] = now + FAILED_COOLDOWN_SEC
                with stats_lock:
                    stats["adds_fail"] += 1

        if ok_count:
            with stats_lock:
                stats["rules_installed"] += ok_count
    
    def count_port_pkts(self, port_id: int) -> dict:
        """Count rx/tx frames for a port."""
        port_stats = self.bfrt_info.table_get("$PORT_STAT")
        data, _ = next(
            port_stats.entry_get(
                self.target, [port_stats.make_key([gc.KeyTuple("$DEV_PORT", port_id)])],
                {"from_hw": True}
            )
        )
        data = data.to_dict()
        return {"rx": data['$FramesReceivedAll'], "tx": data['$FramesTransmittedAll']}


def record_udx_rules(keys: list, epoch_counter_ref: list, gate_by_epoch: bool = True):
    """Record UDX rules and update active_hosts.last_udx.
    Enqueue to pending_queue only after HOT_WINDOW_EPOCHS consecutive epoch hits."""
    if not keys:
        return
    now = time.monotonic()
    if not gate_by_epoch:
        for k in keys:
            pending_queue.put(k)
        with data_lock:
            for k in keys:
                ip_int = unpack_flow_key(k)[0]
                if ip_int not in active_hosts:
                    active_hosts[ip_int] = {"flow_count": 0, "last_udx": None}
                active_hosts[ip_int]["last_udx"] = now
        return
    current_epoch = int(epoch_counter_ref[0])
    min_consecutive = max(2, int(HOT_WINDOW_EPOCHS))
    ready_keys = []
    with data_lock:
        for k in keys:
            state = rule_epoch_seen.get(k)
            if state is None:
                last_seen_epoch = current_epoch
                streak_len = 1
                last_queued_epoch = -1
            else:
                last_seen_epoch, streak_len, last_queued_epoch = state
                if current_epoch == last_seen_epoch + 1:
                    streak_len += 1
                    last_seen_epoch = current_epoch
                elif current_epoch != last_seen_epoch:
                    last_seen_epoch = current_epoch
                    streak_len = 1

            if current_epoch == last_seen_epoch:
                consecutive = streak_len >= min_consecutive
            else:
                consecutive = False
            if consecutive and last_queued_epoch != current_epoch:
                ready_keys.append(k)
                last_queued_epoch = current_epoch
            rule_epoch_seen[k] = (last_seen_epoch, streak_len, last_queued_epoch)

            ip_int = unpack_flow_key(k)[0]
            if ip_int not in active_hosts:
                active_hosts[ip_int] = {"flow_count": 0, "last_udx": None}
            active_hosts[ip_int]["last_udx"] = now
    for k in ready_keys:
        pending_queue.put(k)


def refresh_hot_rules(controller: Bfrt_GRPC_Client, epoch_counter: int, now: float, max_time_sec: float = None):
    """Prune hot-rule tracking by epoch to bound dict growth."""
    min_keep_epoch = int(epoch_counter) - max(2, int(HOT_WINDOW_EPOCHS)) - 1
    if min_keep_epoch >= 0:
        with data_lock:
            stale_keys = [
                k for k, (last_seen_epoch, _, _) in rule_epoch_seen.items()
                if last_seen_epoch < min_keep_epoch
            ]
            for k in stale_keys:
                rule_epoch_seen.pop(k, None)
            hot_rules_count[0] = sum(
                1
                for _, streak_len, _ in rule_epoch_seen.values()
                if streak_len >= max(2, int(HOT_WINDOW_EPOCHS))
            )
    else:
        with data_lock:
            hot_rules_count[0] = sum(
                1
                for _, streak_len, _ in rule_epoch_seen.values()
                if streak_len >= max(2, int(HOT_WINDOW_EPOCHS))
            )


LOOP_INTERVAL_SEC = 0.01  # main-loop select timeout
# Match throughput script: large batches + strict batch add (no per-entry fallback on failure)
MAX_INSTALL_CALL_BATCH = 4096
DEFAULT_INSTALL_BATCH_MIN = 256
DEFAULT_INSTALL_CALL_TARGET_SEC = 0.12
DEFAULT_INSTALL_BACKLOG_BATCHES = 12
DEFAULT_INSTALL_BACKLOG_HIGH_WATERMARK = 50000
DEFAULT_HW_SAMPLE_INTERVAL_SEC = 10.0
DEFAULT_FAILED_CLEAN_INTERVAL_SEC = 0.2
DEFAULT_FAILED_CLEAN_SCAN_BATCH = 1024
DEFAULT_BATCH_ADJUST_INTERVAL_SEC = 0.25


def udx_receiver_thread(
    sock: socket.socket,
    buf: bytearray,
    epoch_counter_ref: list,
    gate_by_epoch: bool,
):
    """Dedicated thread: recv/parse/record from UDX. No BFRT/gRPC."""
    sel = selectors.DefaultSelector()
    sock.setblocking(False)
    sel.register(sock, selectors.EVENT_READ)
    # Short 1ms poll to drain the socket quickly; a 0.5s timeout would throttle pkts_ok growth
    UDX_POLL_TIMEOUT = 0.001
    while True:
        sel.select(timeout=UDX_POLL_TIMEOUT)
        while True:
            try:
                nbytes, _, msg_flags, _ = sock.recvmsg_into([buf], 0, socket.MSG_TRUNC)
            except BlockingIOError:
                break
            except InterruptedError:
                continue
            if msg_flags & socket.MSG_TRUNC:
                with stats_lock:
                    stats["pkts_trunc"] += 1
                continue
            data = bytes(memoryview(buf)[:nbytes])
            keys = parse_datagram_to_keys(data)
            if keys:
                record_udx_rules(keys, epoch_counter_ref, gate_by_epoch=gate_by_epoch)
            else:
                with stats_lock:
                    stats["sock_drop"] += 1


def main_loop(
    sock_path="/tmp/p4_controller.sock",
    rcvbuf_bytes=16 * 1024 * 1024,
    entry_ttl=5000,
    clean_batch_size=1000,
    batch_max=4096,
    install_batch_min=DEFAULT_INSTALL_BATCH_MIN,
    install_call_target_sec=DEFAULT_INSTALL_CALL_TARGET_SEC,
    install_backlog_batches=DEFAULT_INSTALL_BACKLOG_BATCHES,
    install_backlog_high_watermark=DEFAULT_INSTALL_BACKLOG_HIGH_WATERMARK,
    install_budget_sec=RULE_INSTALL_BUDGET_SEC,
    install_strict_batch=True,
    hw_sample_interval_sec=DEFAULT_HW_SAMPLE_INTERVAL_SEC,
    failed_clean_interval_sec=DEFAULT_FAILED_CLEAN_INTERVAL_SEC,
    failed_clean_scan_batch=DEFAULT_FAILED_CLEAN_SCAN_BATCH,
    idle_clean_interval_sec=IDLE_CLEAN_INTERVAL_SEC,
    idle_clean_skip_pending=IDLE_CLEAN_SKIP_PENDING,
    idle_clean_target_per_sec=DEFAULT_IDLE_CLEAN_TARGET_PER_SEC,
    idle_clean_burst=DEFAULT_IDLE_CLEAN_BURST,
    idle_clean_max_calls_per_loop=DEFAULT_IDLE_CLEAN_MAX_CALLS_PER_LOOP,
    idle_clean_poll_timeout_sec=DEFAULT_IDLE_CLEAN_POLL_TIMEOUT_SEC,
    epoch_print_interval_sec=10.0,
    epoch_switch_interval_sec=2.0,
    epoch_csv_path=None,
    shm_name=None,
    update_mode="both",
):
    """
    Single main loop: select-driven UDX RX, periodic bulk install, idle deletes, epoch rotation, stats.
    """
    if update_mode not in ("both", "rules-only"):
        raise ValueError(
            f"invalid update_mode={update_mode}, expected one of: both, rules-only"
        )
    bloom_enabled = update_mode == "both"
    print(f"[mode] update_mode={update_mode}")
    _log_mode = os.environ.get("TSDN_LOG_OUTPUT_MODE", "").strip()
    _mode_tag = f" TSDN_LOG_OUTPUT_MODE={_log_mode}" if _log_mode else ""
    print(
        f"[log]{_mode_tag} epoch_print_sec={epoch_print_interval_sec} "
        f"hw_sample_sec={hw_sample_interval_sec}"
    )

    controller = Bfrt_GRPC_Client(
        entry_ttl=entry_ttl, clean_batch_size=clean_batch_size
    )
    reset_runtime_queues()
    controller.clear_service_table()

    if os.path.exists(sock_path):
        os.unlink(sock_path)
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    sock.bind(sock_path)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, rcvbuf_bytes)
    buf = bytearray(65536)
    epoch_counter_ref = [0]
    gate_by_epoch = bloom_enabled
    threading.Thread(
        target=udx_receiver_thread,
        args=(sock, buf, epoch_counter_ref, gate_by_epoch),
        daemon=True,
    ).start()
    shm_reader = None
    next_shm_retry = 0.0
    if shm_name:
        try:
            shm_reader = ShmRuleRingReader(shm_name)
            shm_reader.clear()
            print(f"[ipc] SHM enabled: {shm_name}")
        except Exception as e:
            print(f"[ipc] SHM not ready ({shm_name}): {e}; will retry")
            next_shm_retry = time.monotonic() + 1.0

    # Bloom init (skipped in rules-only mode)
    if bloom_enabled:
        for e in (0, 1):
            for t in controller.REGISTER_TABLES[e]:
                controller.clear_table(t)
            for t in controller.COUNTER_TABLES[e]:
                controller.clear_table(t)
        controller.set_bloom_epoch(0)
    current_epoch = 0
    next_epoch_switch = (
        time.monotonic() + epoch_switch_interval_sec if bloom_enabled else float("inf")
    )
    csv_file = open(epoch_csv_path, "w", newline="") if epoch_csv_path else None
    csv_writer = csv.writer(csv_file) if csv_file else None
    if csv_writer:
        csv_writer.writerow([
            "timestamp", "interval_cycle", "epoch", "group0", "group1", "switched",
            "in_s", "pend_add_s", "inst_s", "del_s", "pending_delta_s", "add_fail_s",
            "pending", "fail_cd", "hot_rules", "local", "usage", "active_hosts",
            "pkts_ok", "pkts_bad", "pkts_trunc", "batch_ok", "batch_fail", "sock_drop",
            "rx_pkts_s", "tx_pkts_s", "ring_depth", "ring_pushes", "ring_pops", "ring_dropped",
            "install_batch"
        ])
        csv_file.flush()

    last_report = time.monotonic()
    last_active_clean = time.monotonic()
    last_idle_clean = time.monotonic()
    last_rules_in = last_installed = last_pending_add = last_add_fail = 0
    last_deleted = 0
    did_epoch_switch_since_report = False
    epoch_delay_ms_since_report = 0.0
    last_bloom_v0, last_bloom_v1 = 0, 0  # counters read before epoch flip, for stats/print
    last_rx_pkts = controller.count_port_pkts(INCOMING_PORT)["rx"]
    last_tx_pkts = controller.count_port_pkts(OUTGOING_PORT)["tx"]
    install_batch_cap = min(max(1, batch_max), MAX_INSTALL_CALL_BATCH)
    install_batch_floor = min(max(1, install_batch_min), install_batch_cap)
    install_batch_cur = max(install_batch_floor, install_batch_cap)
    last_failed_clean = time.monotonic()
    last_hw_sample = time.monotonic()
    hw_sample_age_ms = 0.0
    cached_usage = -1
    cached_active_num = 0
    cached_rx_pkts_s = 0.0
    cached_tx_pkts_s = 0.0
    install_duty_last = 0.0
    batch_latency_ewma = 0.0
    batch_slow_rounds = 0
    batch_fast_rounds = 0
    last_batch_adjust = time.monotonic()
    last_idle_refill = time.monotonic()
    idle_clean_tokens = min(
        max(1.0, float(idle_clean_burst)),
        max(1.0, float(idle_clean_target_per_sec) * max(0.01, float(idle_clean_interval_sec))),
    )

    def run_epoch_switch_if_due(now_ts: float):
        """Run epoch switch when due; if behind, only advance schedule to avoid burst catch-up stalls."""
        nonlocal current_epoch, next_epoch_switch, last_bloom_v0, last_bloom_v1, did_epoch_switch_since_report, epoch_delay_ms_since_report
        if not bloom_enabled:
            return False, now_ts
        if now_ts < next_epoch_switch:
            return False, now_ts

        scheduled_switch_ts = next_epoch_switch
        c0, c1 = controller.COUNTER_TABLES[current_epoch]
        try:
            last_bloom_v0 = controller.get_counter_value(c0)
            last_bloom_v1 = controller.get_counter_value(c1)
        except Exception:
            last_bloom_v0, last_bloom_v1 = 0, 0
        epoch_counter_ref[0] += 1
        refresh_hot_rules(controller, epoch_counter_ref[0], now_ts, max_time_sec=REFRESH_HOT_MAX_SEC)
        idle_epoch = 1 - current_epoch
        current_epoch = 1 - current_epoch
        controller.set_bloom_epoch(current_epoch)
        # Bloom clear must align with flip so stale epoch state does not skew counts.
        for t in controller.REGISTER_TABLES[idle_epoch]:
            controller.clear_table(t)
        for t in controller.COUNTER_TABLES[idle_epoch]:
            controller.clear_table(t)

        did_epoch_switch_since_report = True
        switch_delay_ms = max(0.0, (now_ts - scheduled_switch_ts) * 1000.0)
        epoch_delay_ms_since_report = max(epoch_delay_ms_since_report, switch_delay_ms)
        now_ts = time.monotonic()
        # Fixed cadence avoids long-term drift after a delayed tick.
        next_epoch_switch = scheduled_switch_ts + epoch_switch_interval_sec
        if next_epoch_switch <= now_ts:
            missed = int((now_ts - next_epoch_switch) // epoch_switch_interval_sec) + 1
            next_epoch_switch += missed * epoch_switch_interval_sec
        return True, now_ts

    try:
        while True:
            now = time.monotonic()
            if shm_name and shm_reader is None and now >= next_shm_retry:
                try:
                    shm_reader = ShmRuleRingReader(shm_name)
                    shm_reader.clear()
                    print(f"[ipc] SHM enabled: {shm_name}")
                except Exception:
                    next_shm_retry = now + 1.0
            # When installs are pending, minimize sleep to reduce idle wait near benchmark throughput.
            if not pending_set:
                sleep_until = min(now + LOOP_INTERVAL_SEC, next_epoch_switch)
                delay = sleep_until - time.monotonic()
                if delay > 0:
                    time.sleep(delay)
            now = time.monotonic()

            # 1) Epoch rotation first (compensated switches after long blocks)
            _, now = run_epoch_switch_if_due(now)

            # 2) Fast path: move UDX/SHM rules into pending_set (main thread)
            if shm_reader is not None:
                shm_keys = shm_reader.drain()
                if shm_keys:
                    with stats_lock:
                        stats["rules_in"] += len(shm_keys)
                    record_udx_rules(shm_keys, epoch_counter_ref, gate_by_epoch=gate_by_epoch)

            pending_target = install_batch_cur * max(1, install_backlog_batches)
            enqueue_added = 0
            drained = 0
            drain_limit = MAX_ENQUEUE_DRAIN_PER_LOOP
            if len(pending_set) >= pending_target:
                drain_limit = min(MAX_ENQUEUE_DRAIN_PER_LOOP, install_batch_cur * 2)
            while drained < drain_limit:
                try:
                    k = pending_queue.get_nowait()
                except queue.Empty:
                    break
                drained += 1
                if k in controller.installed_flows:
                    continue
                until = failed_until.get(k)
                if until is not None and now < until:
                    continue
                if k not in pending_set:
                    pending_set.add(k)
                    enqueue_added += 1
            if enqueue_added:
                with stats_lock:
                    stats["rules_pending_add"] += enqueue_added
            # 3) Rule install phase (stats/idle after)
            install_phase_started = time.monotonic()
            if pending_set:
                install_now = time.monotonic()
                ring_depth_now = 0
                if shm_reader is not None:
                    ring_depth_now = shm_reader.snapshot()["depth"]
                if install_now - last_failed_clean >= failed_clean_interval_sec:
                    last_failed_clean = install_now
                    for k in list(itertools.islice(failed_until.keys(), failed_clean_scan_batch)):
                        if failed_until.get(k, 0) <= install_now:
                            failed_until.pop(k, None)
                dynamic_budget_sec = install_budget_sec
                if len(pending_set) >= install_backlog_high_watermark or ring_depth_now >= install_backlog_high_watermark:
                    dynamic_budget_sec = min(max(install_budget_sec, 0.001) * 1.5, 2.0)
                install_deadline = install_now + max(0.0, dynamic_budget_sec)
                if bloom_enabled:
                    install_deadline = min(
                        install_deadline,
                        max(install_now, next_epoch_switch - EPOCH_SWITCH_MARGIN_SEC),
                    )
                batches_done = 0
                while pending_set and time.monotonic() < install_deadline:
                    now_batch = time.monotonic()
                    take_cap = install_batch_cur
                    if bloom_enabled:
                        est_batch_sec = (
                            batch_latency_ewma
                            if batch_latency_ewma > 0
                            else max(0.001, install_call_target_sec)
                        )
                        remain_to_switch = (
                            next_epoch_switch - now_batch - EPOCH_SWITCH_MARGIN_SEC
                        )
                        # Near flip, avoid starting a batch likely to cross the switch;
                        # briefly pause installs to keep the flip on time.
                        if remain_to_switch <= max(0.001, est_batch_sec * 0.75):
                            break
                        if remain_to_switch < est_batch_sec * 2.0:
                            scale = max(0.2, min(1.0, remain_to_switch / (est_batch_sec * 2.0)))
                            take_cap = max(64, int(install_batch_cur * scale))
                    take_n = min(len(pending_set), max(1, take_cap))
                    keys = [pending_set.pop() for _ in range(take_n)]
                    batch_started = time.monotonic()
                    controller.entry_add_batch(keys, strict_batch=install_strict_batch)
                    batch_elapsed = max(1e-6, time.monotonic() - batch_started)
                    if batch_latency_ewma <= 0:
                        batch_latency_ewma = batch_elapsed
                    else:
                        batch_latency_ewma = batch_latency_ewma * 0.8 + batch_elapsed * 0.2
                    if batch_latency_ewma > install_call_target_sec * 1.8:
                        batch_slow_rounds += 1
                        batch_fast_rounds = 0
                    elif batch_latency_ewma < install_call_target_sec * 0.75:
                        batch_fast_rounds += 1
                        batch_slow_rounds = 0
                    else:
                        batch_slow_rounds = 0
                        batch_fast_rounds = 0
                    adjust_now = time.monotonic()
                    if adjust_now - last_batch_adjust >= DEFAULT_BATCH_ADJUST_INTERVAL_SEC:
                        if batch_slow_rounds >= 2:
                            install_batch_cur = max(
                                install_batch_floor,
                                int(install_batch_cur * 0.8),
                            )
                            batch_slow_rounds = 0
                            last_batch_adjust = adjust_now
                        elif batch_fast_rounds >= 2 and install_batch_cur < install_batch_cap:
                            install_batch_cur = min(
                                install_batch_cap,
                                max(install_batch_cur + 32, int(install_batch_cur * 1.15)),
                            )
                            batch_fast_rounds = 0
                            last_batch_adjust = adjust_now
                    batches_done += 1
                    # Re-check epoch after each batch so large batches do not delay the switch point.
                    _, _ = run_epoch_switch_if_due(time.monotonic())
            install_phase_elapsed = time.monotonic() - install_phase_started

            # 4) Bloom-related: token-bucket idle deletes smooth del/s and avoid slow clear when full
            now = time.monotonic()
            margin = next_epoch_switch - now
            is_backlogged = len(pending_set) >= idle_clean_skip_pending
            refill_now = time.monotonic()
            refill_elapsed = max(0.0, refill_now - last_idle_refill)
            last_idle_refill = refill_now
            idle_clean_tokens = min(
                max(1.0, float(idle_clean_burst)),
                idle_clean_tokens + refill_elapsed * max(0.0, float(idle_clean_target_per_sec)),
            )
            allow_idle_when_backlogged = (
                (bloom_enabled and margin > EPOCH_SWITCH_MARGIN_SEC * 2)
                or (not bloom_enabled)
            )
            can_idle_clean = (
                now - last_idle_clean >= idle_clean_interval_sec
                and (not is_backlogged or allow_idle_when_backlogged)
            )
            if can_idle_clean and idle_clean_tokens >= 1.0:
                idle_calls = 0
                while idle_clean_tokens >= 1.0 and idle_calls < max(1, int(idle_clean_max_calls_per_loop)):
                    if bloom_enabled and (next_epoch_switch - time.monotonic()) <= EPOCH_SWITCH_MARGIN_SEC:
                        break
                    if is_backlogged and not bloom_enabled:
                        call_cap = min(MAX_IDLE_PER_LOOP, max(16, install_batch_cur // 16))
                    elif margin > EPOCH_SWITCH_MARGIN_SEC * 2:
                        call_cap = MAX_IDLE_PER_LOOP
                    else:
                        call_cap = min(10, MAX_IDLE_PER_LOOP)
                    idle_max = min(call_cap, max(1, int(idle_clean_tokens)))
                    removed = controller.idle_entry_batch_clean(
                        timeout=max(0.0, float(idle_clean_poll_timeout_sec)),
                        max_fetch=idle_max,
                    )
                    last_idle_clean = time.monotonic()
                    idle_calls += 1
                    if removed > 0:
                        idle_clean_tokens = max(0.0, idle_clean_tokens - float(removed))
                    else:
                        # Consume a probe token even with nothing to delete, to reduce busy-spin jitter.
                        idle_clean_tokens = max(0.0, idle_clean_tokens - 1.0)
                        break
                    if removed < idle_max:
                        break

            # 5) Stats/CSV use v0,v1 read before the last epoch switch
            report_elapsed = now - last_report
            if report_elapsed >= max(0.1, epoch_print_interval_sec):
                elapsed = max(report_elapsed, 1e-9)
                last_report = now
                with stats_lock:
                    s = dict(stats)
                rin = (s["rules_in"] - last_rules_in) / elapsed
                last_rules_in = s["rules_in"]
                rpend = (s["rules_pending_add"] - last_pending_add) / elapsed
                last_pending_add = s["rules_pending_add"]
                rinst = (s["rules_installed"] - last_installed) / elapsed
                last_installed = s["rules_installed"]
                rdel = (s["rules_deleted"] - last_deleted) / elapsed
                last_deleted = s["rules_deleted"]
                pending_delta_s = rpend - rinst
                add_fail_s = (s["adds_fail"] - last_add_fail) / elapsed
                last_add_fail = s["adds_fail"]
                install_duty_last = min(100.0, max(0.0, (install_phase_elapsed / elapsed) * 100.0))

                if now - last_hw_sample >= hw_sample_interval_sec:
                    last_hw_sample = now
                    try:
                        cur_rx = controller.count_port_pkts(INCOMING_PORT)["rx"]
                        cur_tx = controller.count_port_pkts(OUTGOING_PORT)["tx"]
                        cached_rx_pkts_s = (cur_rx - last_rx_pkts) / max(hw_sample_interval_sec, 1e-9)
                        cached_tx_pkts_s = (cur_tx - last_tx_pkts) / max(hw_sample_interval_sec, 1e-9)
                        last_rx_pkts = cur_rx
                        last_tx_pkts = cur_tx
                    except Exception:
                        pass
                    try:
                        cached_usage = controller.get_table_usage()
                    except Exception:
                        pass
                    try:
                        cached_active_num = controller.get_active_host_count()
                    except Exception:
                        pass
                hw_sample_age_ms = max(0.0, (now - last_hw_sample) * 1000.0)

                pend_sz = len(pending_set)
                fail_sz = len(failed_until)
                hot_sz = hot_rules_count[0]
                v0, v1 = last_bloom_v0, last_bloom_v1
                local_num = controller.get_local_flow_entry_num()
                ring_depth = ring_pushes = ring_pops = ring_dropped = 0
                if shm_reader is not None:
                    rs = shm_reader.snapshot()
                    ring_depth = rs["depth"]
                    ring_pushes = rs["pushes"]
                    ring_pops = rs["pops"]
                    ring_dropped = rs["dropped"]
                if now - last_active_clean >= ACTIVE_CLEAN_INTERVAL:
                    last_active_clean = now
                    with data_lock:
                        to_del = [
                            ip_int
                            for ip_int, v in list(active_hosts.items())
                            if v["flow_count"] <= 0
                            and (v["last_udx"] is None or now - v["last_udx"] >= UDX_ACTIVE_SEC)
                        ]
                        for ip_int in to_del:
                            active_hosts.pop(ip_int, None)
                if csv_writer:
                    interval_cycle = epoch_switch_interval_sec if bloom_enabled else 0
                    csv_writer.writerow([
                        time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
                        interval_cycle,
                        current_epoch, v0, v1,
                        1 if did_epoch_switch_since_report else 0,
                        round(rin, 2), round(rpend, 2), round(rinst, 2), round(rdel, 2), round(pending_delta_s, 2), round(add_fail_s, 2),
                        pend_sz, fail_sz, hot_sz, local_num, cached_usage, cached_active_num,
                        s["pkts_ok"], s["pkts_bad"], s["pkts_trunc"],
                        s["batches_ok"], s["batches_fail"], s["sock_drop"],
                        round(cached_rx_pkts_s, 2), round(cached_tx_pkts_s, 2),
                        ring_depth, ring_pushes, ring_pops, ring_dropped,
                        install_batch_cur,
                    ])
                    csv_file.flush()
                print(
                    build_status_report(
                        now_dt=datetime.now(),
                        current_epoch=current_epoch,
                        did_epoch_switch=did_epoch_switch_since_report,
                        epoch_delay_ms=epoch_delay_ms_since_report,
                        v0=v0,
                        v1=v1,
                        rin=rin,
                        rpend=rpend,
                        rinst=rinst,
                        rdel=rdel,
                        pending_delta_s=pending_delta_s,
                        add_fail_s=add_fail_s,
                        install_batch=install_batch_cur,
                        pend_sz=pend_sz,
                        fail_sz=fail_sz,
                        hot_sz=hot_sz,
                        local_num=local_num,
                        usage=cached_usage,
                        active_num=cached_active_num,
                        s=s,
                        rx_pkts_s=cached_rx_pkts_s,
                        tx_pkts_s=cached_tx_pkts_s,
                        ring_depth=ring_depth,
                        ring_pushes=ring_pushes,
                        ring_pops=ring_pops,
                        ring_dropped=ring_dropped,
                    )
                )
                did_epoch_switch_since_report = False
                epoch_delay_ms_since_report = 0.0
    finally:
        if shm_reader is not None:
            shm_reader.close()
        if csv_file:
            csv_file.close()


if __name__ == "__main__":
    import argparse

    def _apply_log_output_mode_env_defaults():
        """Match controller.env case preset when launching without start_controller.sh."""
        m = (os.environ.get("TSDN_LOG_OUTPUT_MODE") or "").strip().lower()
        if not m:
            return
        if m in ("debug", "verbose"):
            os.environ.setdefault("BFR_EPOCH_PRINT_SEC", "0.5")
            os.environ.setdefault("BFR_HW_SAMPLE_INTERVAL_MS", "1000")
        elif m in ("daemon", "prod", "production", "longrun"):
            os.environ.setdefault("BFR_EPOCH_PRINT_SEC", "10")
            os.environ.setdefault("BFR_HW_SAMPLE_INTERVAL_MS", "10000")

    _apply_log_output_mode_env_defaults()

    def _fmt_param_token(value: float) -> str:
        token = f"{value:g}"
        return token.replace(".", "p")

    parser = argparse.ArgumentParser(
        description="BFRT combined controller: UDX rules + bloom epoch + idle clean + active hosts"
    )
    parser.add_argument(
        "--sock",
        default="/tmp/p4_controller.sock",
        help="Unix domain socket path",
    )
    parser.add_argument(
        "--entry-ttl", type=int, default=5000, help="Entry TTL (ms)",
    )
    parser.add_argument(
        "--install-batch-size",
        type=int,
        default=int(os.environ.get("BFR_INSTALL_BATCH_SIZE", "1024")),
        help="Rule install batch size upper bound per gRPC call (default: 1024)",
    )
    parser.add_argument(
        "--install-batch-min",
        type=int,
        default=int(os.environ.get("BFR_INSTALL_BATCH_MIN", "256")),
        help="Rule install batch size lower bound for adaptive tuning (default: 256)",
    )
    parser.add_argument(
        "--install-call-target-ms",
        type=float,
        default=float(os.environ.get("BFR_INSTALL_CALL_TARGET_MS", "120")),
        help="Adaptive batch target call latency in ms (default: 120)",
    )
    parser.add_argument(
        "--install-backlog-batches",
        type=int,
        default=int(os.environ.get("BFR_INSTALL_BACKLOG_BATCHES", "12")),
        help="Target pending depth in batch units before queue drain throttles (default: 12)",
    )
    parser.add_argument(
        "--install-backlog-high-watermark",
        type=int,
        default=int(os.environ.get("BFR_INSTALL_BACKLOG_HIGH_WATERMARK", "50000")),
        help="Pending high watermark for temporary install budget boost (default: 50000)",
    )
    parser.add_argument(
        "--install-budget-ms",
        type=float,
        default=float(os.environ.get("BFR_INSTALL_BUDGET_MS", "800")),
        help="Per-loop install time budget in ms (default: 800)",
    )
    parser.add_argument(
        "--install-fallback-single",
        action="store_true",
        help="Enable single-entry fallback when batch add fails (default: disabled for throughput)",
    )
    parser.add_argument(
        "--idle-clean-interval-ms",
        type=float,
        default=float(os.environ.get("BFR_IDLE_CLEAN_INTERVAL_MS", "200")),
        help="Idle cleanup interval in ms (default: 200)",
    )
    parser.add_argument(
        "--idle-clean-skip-pending",
        type=int,
        default=int(os.environ.get("BFR_IDLE_CLEAN_SKIP_PENDING", "4096")),
        help="Skip idle cleanup when pending rules exceed this value (default: 4096)",
    )
    parser.add_argument(
        "--idle-clean-target-per-sec",
        type=float,
        default=float(os.environ.get("BFR_IDLE_CLEAN_TARGET_PER_SEC", "320")),
        help="Target idle delete throughput for token-bucket scheduler (default: 320)",
    )
    parser.add_argument(
        "--idle-clean-burst",
        type=float,
        default=float(os.environ.get("BFR_IDLE_CLEAN_BURST", str(int(MAX_IDLE_PER_LOOP * 8)))),
        help="Token-bucket burst size for idle cleanup (default: 640)",
    )
    parser.add_argument(
        "--idle-clean-max-calls-per-loop",
        type=int,
        default=int(os.environ.get("BFR_IDLE_CLEAN_MAX_CALLS_PER_LOOP", "4")),
        help="Max idle cleanup calls per main loop (default: 4)",
    )
    parser.add_argument(
        "--idle-clean-poll-timeout-ms",
        type=float,
        default=float(os.environ.get("BFR_IDLE_CLEAN_POLL_TIMEOUT_MS", "2")),
        help="Per-idle-clean call notification poll timeout in ms (default: 2)",
    )
    parser.add_argument(
        "--hw-sample-interval-ms",
        type=float,
        default=float(os.environ.get("BFR_HW_SAMPLE_INTERVAL_MS", "2000")),
        help="Sampling interval for heavy hardware stats (default: 2000)",
    )
    parser.add_argument(
        "--failed-clean-interval-ms",
        type=float,
        default=float(os.environ.get("BFR_FAILED_CLEAN_INTERVAL_MS", "200")),
        help="Interval for incremental failed_until cleanup (default: 200)",
    )
    parser.add_argument(
        "--failed-clean-scan-batch",
        type=int,
        default=int(os.environ.get("BFR_FAILED_CLEAN_SCAN_BATCH", "1024")),
        help="Max failed_until entries scanned per cleanup step (default: 1024)",
    )
    parser.add_argument(
        "--epoch-print",
        type=float,
        default=float(os.environ.get("BFR_EPOCH_PRINT_SEC", "10")),
        help="Status/CSV print interval in seconds (env BFR_EPOCH_PRINT_SEC; preset via TSDN_LOG_OUTPUT_MODE)",
    )
    parser.add_argument(
        "--epoch-switch",
        type=float,
        default=float(os.environ.get("BFR_EPOCH_SWITCH_SEC", "2.0")),
        help="Bloom epoch switch interval in seconds (env BFR_EPOCH_SWITCH_SEC)",
    )
    parser.add_argument(
        "--hot-window",
        type=int,
        default=2,
        help="Hot rule window: must appear in all of past N epochs (default: 2)",
    )
    parser.add_argument(
        "--shm-name",
        default=os.environ.get("P4_RULE_SHM_NAME", DEFAULT_SHM_NAME),
        help="POSIX SHM name for rule ring, e.g. /p4_rule_ring",
    )
    parser.add_argument(
        "--update-mode",
        choices=("both", "rules-only"),
        default=os.environ.get("BFR_UPDATE_MODE", os.environ.get("TSDN_UPDATE_MODE", "both")),
        help="Update mode: both (bloom + rules) or rules-only (skip bloom epoch ops)",
    )
    args = parser.parse_args()

    HOT_WINDOW_EPOCHS = args.hot_window
    log_dir = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "log",
        "runs",
        "latest",
    )
    os.makedirs(log_dir, exist_ok=True)
    epoch_switch_token = _fmt_param_token(args.epoch_switch)
    epoch_print_token = _fmt_param_token(args.epoch_print)
    epoch_csv = os.path.join(
        log_dir,
        f"occ_sw{epoch_switch_token}s_pr{epoch_print_token}s_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
    )
    main_loop(
        sock_path=args.sock,
        entry_ttl=args.entry_ttl,
        clean_batch_size=1000,
        batch_max=max(1, args.install_batch_size),
        install_batch_min=max(1, args.install_batch_min),
        install_call_target_sec=max(0.001, args.install_call_target_ms / 1000.0),
        install_backlog_batches=max(1, args.install_backlog_batches),
        install_backlog_high_watermark=max(1, args.install_backlog_high_watermark),
        install_budget_sec=max(0.0, args.install_budget_ms / 1000.0),
        install_strict_batch=not args.install_fallback_single,
        hw_sample_interval_sec=max(0.1, args.hw_sample_interval_ms / 1000.0),
        failed_clean_interval_sec=max(0.01, args.failed_clean_interval_ms / 1000.0),
        failed_clean_scan_batch=max(1, args.failed_clean_scan_batch),
        idle_clean_interval_sec=max(0.0, args.idle_clean_interval_ms / 1000.0),
        idle_clean_skip_pending=max(0, args.idle_clean_skip_pending),
        idle_clean_target_per_sec=max(0.0, args.idle_clean_target_per_sec),
        idle_clean_burst=max(1.0, args.idle_clean_burst),
        idle_clean_max_calls_per_loop=max(1, args.idle_clean_max_calls_per_loop),
        idle_clean_poll_timeout_sec=max(0.0, args.idle_clean_poll_timeout_ms / 1000.0),
        epoch_print_interval_sec=args.epoch_print,
        epoch_switch_interval_sec=args.epoch_switch,
        epoch_csv_path=epoch_csv,
        shm_name=args.shm_name if args.shm_name else None,
        update_mode=args.update_mode,
    )
