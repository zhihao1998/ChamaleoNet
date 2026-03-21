#!/usr/bin/python3
"""
Combined BFRT controller: bloom epoch rotation + UDX rule install + idle cleanup + active host tracking.
UDX 接收独立线程，BFRT/gRPC 操作集中在主线程（gRPC 非线程安全）。
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
from datetime import datetime

# =========================
# P4 用户态下发报文协议
# =========================
P4_MAGIC = 0x5034
P4_VER = 1
P4_OP_INSTALL = 1

HDR = struct.Struct("!HBBHH")
RULE = struct.Struct("!BBHI")
HDR_SIZE = HDR.size
RULE_SIZE = RULE.size

# =========================
# 统计
# =========================
stats = {
    "pkts_ok": 0,
    "pkts_bad": 0,
    "pkts_trunc": 0,
    "sock_drop": 0,
    "rules_in": 0,
    "rules_pending_add": 0,
    "rules_installed": 0,
    "batches_ok": 0,
    "batches_fail": 0,
    "adds_fail": 0,
}
stats_lock = threading.Lock()
data_lock = threading.Lock()  # 保护 rule_epoch_seen, active_hosts, epoch_counter_ref
# =========================
# 控制器依赖（Tofino BFRT）
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


# =========================
# 全局：待下发规则集合、失败冷却、active host 状态
# pending_set/failed_until 仅主线程访问；rule_epoch_seen/active_hosts 需 data_lock
# =========================
pending_set = set()
failed_until = {}
FAILED_COOLDOWN_SEC = 0.2
FAILED_MAX_SIZE = 200000

# 主机活跃判定：有 UDX 规则传入或远端仍有未过期表项即视为活跃
# active_hosts: ip_int -> {"flow_count": int, "last_udx": float}
active_hosts = {}
UDX_ACTIVE_SEC = 60.0  # UDX 侧最近收到规则后仍视为活跃的秒数

# 热点规则：过去 N 个 epoch 内重复出现的规则才下发，短暂流由 bloom filter 过滤
# rule_epoch_seen: flow_key -> set of epoch_index
rule_epoch_seen = {}
HOT_WINDOW_EPOCHS = 5   # 观察窗口：过去 N 个 epoch
HOT_MIN_EPOCHS = 2      # 至少出现在几个 epoch 才视为热点

# 性能调优（高负载 ~65k flows, 20k pending）
MAX_IDLE_PER_LOOP = 80   # 每轮最多处理 idle 数，避免主循环长时间阻塞
MAX_PUSH_PER_LOOP = 2048  # 每轮最多下发规则数（约 1 批），避免一次 20k 导致主循环阻塞 10-20 秒
ACTIVE_CLEAN_INTERVAL = 5.0  # active_hosts 清理间隔(秒)，减轻 65k 级遍历
# 优先保证 bloom 清理/占用读取按固定间隔准时执行，可牺牲部分待安装规则
RULE_INSTALL_BUDGET_SEC = 0.2   # 每轮规则下发时间预算
EPOCH_SWITCH_MARGIN_SEC = 0.05  # 规则安装必须在下次 bloom 前此时刻停止，保证 bloom 准时
REFRESH_HOT_MAX_SEC = 0.35      # refresh_hot_rules 单次最多计算时间
PENDING_CAP_FOR_BLOOM = 50000  # 若 pending 超过此值且接近 bloom 时刻则丢弃超出部分，保证不拖慢清理/读取
hot_rules_count = [0]  # 缓存，由 refresh_hot_rules 更新

INCOMING_PORT = 160
OUTGOING_PORT = 140

def parse_datagram_to_keys(data: bytes):
    """成功返回 list[int] (packed keys)，失败返回 None。更新 stats 时持 stats_lock。"""
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


class Bfrt_GRPC_Client:
    """合并：bloom epoch 管理 + active_host_tbl 规则下发/过期删除 + active host 维护"""

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
        """清空指定表（寄存器/计数器）"""
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
        """返回 counter 的 $COUNTER_SPEC_PKTS 值"""
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
        """当前活跃主机数：flow_count>0 或 last_udx 在 UDX_ACTIVE_SEC 内"""
        now = time.monotonic()
        with data_lock:
            return sum(
                1
                for v in active_hosts.values()
                if v["flow_count"] > 0
                or (v["last_udx"] is not None and now - v["last_udx"] < UDX_ACTIVE_SEC)
            )

    def idle_entry_batch_clean(self, timeout=0.01, max_fetch=MAX_IDLE_PER_LOOP):
        """从 gRPC 取 idle 通知，批量删表项。max_fetch 限制每轮 gRPC 调用数，避免主循环长时间阻塞"""
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

        return len(removed_keys)

    def entry_add_batch(self, keys_batch: list):
        """批量安装规则，并更新 installed_flows / active_hosts"""
        keys_batch = [k for k in keys_batch if k not in self.installed_flows]
        if not keys_batch:
            return

        key_list = []
        data_list = []
        entry_triples = []
        for k in keys_batch:
            ip_int, port, proto = unpack_flow_key(k)
            entry_triples.append((ip_int, port, proto))
            service_keys = self.service_table.make_key(
                [
                    gc.KeyTuple("meta.internal_ip", int_to_ip(ip_int)),
                    gc.KeyTuple("meta.internal_port", port),
                    gc.KeyTuple("meta.ip_protocol", proto),
                ]
            )
            key_list.append(service_keys)
            data_list.append(
                self.service_table.make_data(
                    [gc.DataTuple("$ENTRY_TTL", self.entry_ttl)],
                    "Ingress.drop",
                )
            )

        try:
            self.service_table.entry_add(self.target, key_list, data_list)
            for k in keys_batch:
                self.installed_flows.add(k)
            with data_lock:
                for k in keys_batch:
                    ip_int = unpack_flow_key(k)[0]
                    if ip_int not in active_hosts:
                        active_hosts[ip_int] = {"flow_count": 0, "last_udx": None}
                    active_hosts[ip_int]["flow_count"] += 1
            with stats_lock:
                stats["batches_ok"] += 1
                stats["rules_installed"] += len(keys_batch)
            return
        except Exception:
            with stats_lock:
                stats["batches_fail"] += 1

        now = time.monotonic()
        ok_count = 0
        for k, (ip_int, port, proto) in zip(keys_batch, entry_triples):
            try:
                one_key = self.service_table.make_key(
                    [
                        gc.KeyTuple("meta.internal_ip", int_to_ip(ip_int)),
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
        """统计 port 的收发包数"""
        port_stats = self.bfrt_info.table_get("$PORT_STAT")
        data, _ = next(
            port_stats.entry_get(
                self.target, [port_stats.make_key([gc.KeyTuple("$DEV_PORT", port_id)])],
                {"from_hw": True}
            )
        )
        data = data.to_dict()
        return {"rx": data['$FramesReceivedAll'], "tx": data['$FramesTransmittedAll']}


def record_udx_rules(keys: list, epoch_counter_ref: list):
    """记录 UDX 收到的规则及其出现的 epoch，并更新 active_hosts.last_udx。
    写时修剪：单 key 的 epoch 集合过大时在此处修剪，避免 refresh_hot_rules 持锁做海量写回阻塞收包。"""
    if not keys:
        return
    now = time.monotonic()
    with data_lock:
        epoch = epoch_counter_ref[0]
        min_epoch = epoch - HOT_WINDOW_EPOCHS
        for k in keys:
            s = rule_epoch_seen.setdefault(k, set())
            s.add(epoch)
            if len(s) > HOT_WINDOW_EPOCHS * 2:
                rule_epoch_seen[k] = {e for e in s if e >= min_epoch}
            ip_int = unpack_flow_key(k)[0]
            if ip_int not in active_hosts:
                active_hosts[ip_int] = {"flow_count": 0, "last_udx": None}
            active_hosts[ip_int]["last_udx"] = now


def refresh_hot_rules(controller: Bfrt_GRPC_Client, epoch_counter: int, now: float, max_time_sec: float = None):
    """epoch 切换后调用：修剪 rule_epoch_seen（仅删空 key），将热点规则加入 pending_set。max_time_sec 超时则中断。
    不在持锁时做海量 rule_epoch_seen[k]=trimmed 写回（由 record_udx_rules 写时修剪），避免长时间阻塞 UDX 收包。"""
    min_epoch = epoch_counter - HOT_WINDOW_EPOCHS
    deadline = (time.monotonic() + max_time_sec) if max_time_sec else None
    with data_lock:
        items = [(k, set(epochs)) for k, epochs in rule_epoch_seen.items()]
    to_prune = []
    to_add_pending = []
    hot_cnt = 0
    installed = controller.installed_flows
    for k, epochs in items:
        if deadline is not None and time.monotonic() >= deadline:
            break
        trimmed = {e for e in epochs if e >= min_epoch}
        if not trimmed:
            to_prune.append(k)
            continue
        if len(trimmed) >= HOT_MIN_EPOCHS:
            hot_cnt += 1
            if k in installed:
                continue
            until = failed_until.get(k)
            if until is not None and now < until:
                continue
            to_add_pending.append(k)
    with data_lock:
        for k in to_prune:
            rule_epoch_seen.pop(k, None)
        for k in to_add_pending:
            pending_set.add(k)
        hot_rules_count[0] = hot_cnt
    if to_add_pending:
        with stats_lock:
            stats["rules_pending_add"] += len(to_add_pending)


LOOP_INTERVAL_SEC = 0.01  # 主循环 select 超时


def udx_receiver_thread(sock: socket.socket, buf: bytearray, epoch_counter_ref: list):
    """独立线程：从 UDX 收包、解析、记录。不触碰 BFRT/gRPC。"""
    sel = selectors.DefaultSelector()
    sock.setblocking(False)
    sel.register(sock, selectors.EVENT_READ)
    # 短超时(1ms)以便及时排空 socket，避免 0.5s 导致收包速率受限、pkts_ok 增长过慢
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
                record_udx_rules(keys, epoch_counter_ref)
            else:
                with stats_lock:
                    stats["sock_drop"] += 1


def main_loop(
    sock_path="/tmp/p4_controller.sock",
    rcvbuf_bytes=16 * 1024 * 1024,
    entry_ttl=5000,
    clean_batch_size=1000,
    batch_max=4096,
    epoch_print_interval_sec=1.0,
    epoch_switch_interval_sec=2.0,
    epoch_csv_path=None,
):
    """
    单主循环：select 驱动 UDX 接收，周期性完成批量下发、idle 删除、epoch 轮换、统计打印。
    """
    controller = Bfrt_GRPC_Client(
        entry_ttl=entry_ttl, clean_batch_size=clean_batch_size
    )
    controller.clear_service_table()

    if os.path.exists(sock_path):
        os.unlink(sock_path)
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    sock.bind(sock_path)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, rcvbuf_bytes)
    buf = bytearray(65536)
    epoch_counter_ref = [0]
    threading.Thread(target=udx_receiver_thread, args=(sock, buf, epoch_counter_ref), daemon=True).start()

    # Bloom 初始化
    for e in (0, 1):
        for t in controller.REGISTER_TABLES[e]:
            controller.clear_table(t)
        for t in controller.COUNTER_TABLES[e]:
            controller.clear_table(t)
    controller.set_bloom_epoch(0)
    current_epoch = 0
    next_epoch_switch = time.monotonic() + epoch_switch_interval_sec
    csv_file = open(epoch_csv_path, "w", newline="") if epoch_csv_path else None
    csv_writer = csv.writer(csv_file) if csv_file else None
    if csv_writer:
        csv_writer.writerow([
            "timestamp", "interval_cycle", "epoch", "group0", "group1", "switched",
            "in_s", "pend_add_s", "inst_s", "add_fail_s",
            "pending", "fail_cd", "hot_rules", "local", "usage", "active_hosts",
            "pkts_ok", "pkts_bad", "pkts_trunc", "batch_ok", "batch_fail", "sock_drop",
            "rx_pkts_s", "tx_pkts_s"
        ])
        csv_file.flush()

    last_report = time.monotonic()
    last_active_clean = time.monotonic()
    last_rules_in = last_installed = last_pending_add = last_add_fail = 0
    did_epoch_switch_since_report = False
    last_bloom_v0, last_bloom_v1 = 0, 0  # 在 epoch 轮换前读到的计数，供统计/打印用
    last_rx_pkts = controller.count_port_pkts(INCOMING_PORT)["rx"]
    last_tx_pkts = controller.count_port_pkts(OUTGOING_PORT)["tx"]

    try:
        while True:
            now = time.monotonic()
            # 避免睡过 epoch 切换点：只睡到 min(下个 loop 间隔, 下次 bloom 时刻)
            sleep_until = min(now + LOOP_INTERVAL_SEC, next_epoch_switch)
            delay = sleep_until - time.monotonic()
            if delay > 0:
                time.sleep(delay)
            now = time.monotonic()

            # 1. 优先：epoch 轮换（bloom 定期清理与轮换）；轮换前先读当前 epoch 的 v0,v1
            if now >= next_epoch_switch:
                c0, c1 = controller.COUNTER_TABLES[current_epoch]
                try:
                    last_bloom_v0 = controller.get_counter_value(c0)
                    last_bloom_v1 = controller.get_counter_value(c1)
                except Exception:
                    last_bloom_v0, last_bloom_v1 = 0, 0
                epoch_counter_ref[0] += 1
                refresh_hot_rules(controller, epoch_counter_ref[0], now, max_time_sec=REFRESH_HOT_MAX_SEC)
                idle_epoch = 1 - current_epoch
                current_epoch = 1 - current_epoch
                controller.set_bloom_epoch(current_epoch)
                for t in controller.REGISTER_TABLES[idle_epoch]:
                    controller.clear_table(t)
                for t in controller.COUNTER_TABLES[idle_epoch]:
                    controller.clear_table(t)
                next_epoch_switch += epoch_switch_interval_sec
                did_epoch_switch_since_report = True

            # 2. bloom 相关：idle 删除（接近 epoch 切换时减少量，避免 gRPC 拖慢下一轮 bloom）
            margin = next_epoch_switch - now
            idle_max = MAX_IDLE_PER_LOOP if margin > EPOCH_SWITCH_MARGIN_SEC * 2 else min(10, MAX_IDLE_PER_LOOP)
            controller.idle_entry_batch_clean(max_fetch=idle_max)

            # 3. 统计与 csv 使用上次 epoch 轮换前读到的 v0,v1
            v0, v1 = last_bloom_v0, last_bloom_v1

            # 4. 优先：统计与 csv 记录（每秒）
            if now - last_report >= 1.0:
                last_report = now
                with stats_lock:
                    s = dict(stats)
                rin = s["rules_in"] - last_rules_in
                last_rules_in = s["rules_in"]
                rpend = s["rules_pending_add"] - last_pending_add
                last_pending_add = s["rules_pending_add"]
                rinst = s["rules_installed"] - last_installed
                last_installed = s["rules_installed"]
                add_fail_s = s["adds_fail"] - last_add_fail
                last_add_fail = s["adds_fail"]
                pend_sz = len(pending_set)
                fail_sz = len(failed_until)
                hot_sz = hot_rules_count[0]
                cur_rx = controller.count_port_pkts(INCOMING_PORT)["rx"]
                cur_tx = controller.count_port_pkts(OUTGOING_PORT)["tx"]
                rx_pkts_s = cur_rx - last_rx_pkts
                tx_pkts_s = cur_tx - last_tx_pkts
                last_rx_pkts = cur_rx
                last_tx_pkts = cur_tx
                try:
                    usage = controller.get_table_usage()
                except Exception:
                    usage = -1
                local_num = controller.get_local_flow_entry_num()
                active_num = controller.get_active_host_count()
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
                    csv_writer.writerow([
                        time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
                        epoch_switch_interval_sec,
                        current_epoch, v0, v1,
                        1 if did_epoch_switch_since_report else 0,
                        rin, rpend, rinst, add_fail_s,
                        pend_sz, fail_sz, hot_sz, local_num, usage, active_num,
                        s["pkts_ok"], s["pkts_bad"], s["pkts_trunc"],
                        s["batches_ok"], s["batches_fail"], s["sock_drop"],
                        rx_pkts_s, tx_pkts_s,
                    ])
                    csv_file.flush()
                did_epoch_switch_since_report = False
                print(
                    f"[{datetime.now().strftime('%H:%M:%S')}] "
                    f"in/s={rin} pend_add/s={rpend} inst/s={rinst} add_fail/s={add_fail_s} "
                    f"pending={pend_sz} fail_cd={fail_sz} hot_rules={hot_sz} local={local_num} usage={usage} "
                    f"active_hosts={active_num} "
                    f"bloom_epoch={current_epoch} bloom_g0={v0} bloom_g1={v1} "
                    f"pkts_ok={s['pkts_ok']} bad={s['pkts_bad']} trunc={s['pkts_trunc']} "
                    f"batch_ok={s['batches_ok']} batch_fail={s['batches_fail']} sock_drop={s['sock_drop']} "
                    f"rx_pkts/s={rx_pkts_s} tx_pkts/s={tx_pkts_s}"
                )

            # 5. 规则安装（时间预算内执行，超时则本轮丢弃/延后，保证下一轮 bloom 不迟到）
            margin = next_epoch_switch - now
            if pending_set and margin > EPOCH_SWITCH_MARGIN_SEC:
                # 若 pending 过多且已接近 bloom 时刻，丢弃超出部分，避免下一轮被安装拖住
                if len(pending_set) > PENDING_CAP_FOR_BLOOM and margin < 0.5:
                    excess = len(pending_set) - PENDING_CAP_FOR_BLOOM
                    for _ in range(min(excess, 20000)):
                        if pending_set:
                            pending_set.pop()
                for k in list(failed_until.keys())[:5000]:
                    if failed_until.get(k, 0) <= now:
                        failed_until.pop(k, None)
                install_deadline = now + RULE_INSTALL_BUDGET_SEC
                # 每批较小（512），便于频繁检查 install_deadline，避免单批 gRPC 过长拖过 bloom
                install_batch = min(512, batch_max)
                while pending_set and time.monotonic() < install_deadline:
                    keys = list(pending_set)[:min(MAX_PUSH_PER_LOOP, len(pending_set))]
                    for k in keys:
                        pending_set.discard(k)
                    for i in range(0, len(keys), install_batch):
                        if time.monotonic() >= install_deadline:
                            for k in keys[i:]:
                                pending_set.add(k)
                            break
                        controller.entry_add_batch(keys[i : i + install_batch])
                    if time.monotonic() >= install_deadline:
                        break
    finally:
        if csv_file:
            csv_file.close()


if __name__ == "__main__":
    import argparse

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
        "--epoch-print", type=float, default=1.0,
        help="Bloom epoch print interval (sec)",
    )
    parser.add_argument(
        "--epoch-switch", type=float, default=2.0,
        help="Bloom epoch switch interval (sec)",
    )
    parser.add_argument(
        "--hot-window",
        type=int,
        default=5,
        help="Hot rule window: past N epochs (default: 5)",
    )
    parser.add_argument(
        "--hot-min",
        type=int,
        default=2,
        help="Min epochs a rule must appear to be hot (default: 2)",
    )
    args = parser.parse_args()

    HOT_WINDOW_EPOCHS = args.hot_window
    HOT_MIN_EPOCHS = args.hot_min
    epoch_csv = f"bfrt_log/{datetime.now().strftime('%Y%m%d_%H%M%S')}_bloom_occupancy.csv"
    main_loop(
        sock_path=args.sock,
        entry_ttl=args.entry_ttl,
        clean_batch_size=1000,
        batch_max=2048,
        epoch_print_interval_sec=args.epoch_print,
        epoch_switch_interval_sec=args.epoch_switch,
        epoch_csv_path=epoch_csv,
    )
