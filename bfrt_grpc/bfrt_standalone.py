#!/usr/bin/python3
import binascii
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

HDR = struct.Struct("!HBBHH")  # magic, ver, op, count, reserved
RULE = struct.Struct("!BBHI")  # proto, rsv, port, ipv4(int)
HDR_SIZE = HDR.size
RULE_SIZE = RULE.size

# =========================
# 统计
# =========================
stats = {
    "pkts_ok": 0,
    "pkts_bad": 0,
    "pkts_trunc": 0,
    "sock_drop": 0,  # recv 侧主动丢（比如 parse 失败不计）
    "rules_in": 0,
    "rules_pending_add": 0,  # 加入 pending 的条目数（已去重后）
    "rules_installed": 0,  # 成功写入/视为写入的条目数
    "batches_ok": 0,
    "batches_fail": 0,
    "adds_fail": 0,  # 单条写入失败次数
}
stats_lock = threading.Lock()

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


# =========================
# packed key: ip(32) + port(16) + proto(8) => 56-bit in int
# =========================
def flow_key(ip_int: int, port: int, proto: int) -> int:
    return ((ip_int & 0xFFFFFFFF) << 24) | ((port & 0xFFFF) << 8) | (proto & 0xFF)


def unpack_flow_key(k: int):
    proto = k & 0xFF
    port = (k >> 8) & 0xFFFF
    ip_int = (k >> 24) & 0xFFFFFFFF
    return ip_int, port, proto


# =========================
# 全局简化去重：pending_set 是唯一“待下发”集合
# =========================
pending_set = set()  # set[int]
pending_lock = threading.Lock()

# 为了避免某些异常导致“同一条一直重试刷屏”，加一个很轻的失败冷却
failed_until = {}  # dict[int -> float(monotonic)]
FAILED_COOLDOWN_SEC = 0.2
FAILED_MAX_SIZE = 200000  # 防止 dict 无限增长


def parse_datagram_to_keys(data: bytes):
    """
    成功返回 list[int] (packed keys)，失败返回 None
    """
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

        # 本地已安装集合（只在“确认成功/或确认不必再重试”时写入）
        self.installed_flows = set()  # set[int]
        self.installed_flows_lock = threading.Lock()

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
            5000,
        )

        self.entry_ttl = entry_ttl
        self.clean_batch_size = clean_batch_size

    def __getattr__(self, name):
        return getattr(self.interface, name)

    def clear_service_table(self):
        try:
            self.service_table.entry_del(self.target, [])
        except Exception:
            print("Problem clearing active service table")

    def get_table_usage(self) -> int:
        return int(next(self.service_table.usage_get(self.target, flags={"from_hw": False})))

    def get_local_flow_entry_num(self) -> int:
        with self.installed_flows_lock:
            return len(self.installed_flows)

    def idle_entry_batch_clean(self):
        """
        保留原逻辑：通过 idletime notification 批量删硬件表项
        并同步更新 installed_flows（以及 failed_until，避免残留）
        """
        key_list = []
        removed_keys = []

        while len(key_list) < self.clean_batch_size:
            try:
                idle_notification = self.interface.idletime_notification_get(timeout=0.2)
                recv_key = self.bfrt_info.key_from_idletime_notification(idle_notification)
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
                # 删失败就不动本地集合，避免更不一致
                return 0

            # 删成功再更新本地
            with self.installed_flows_lock:
                for k in removed_keys:
                    self.installed_flows.discard(k)
            with pending_lock:
                for k in removed_keys:
                    failed_until.pop(k, None)

        return 0

    def entry_add_batch(self, keys_batch):
        """
        keys_batch: list[int] packed keys
        目标：
          - 尽可能批量 entry_add
          - 若批量失败，退化到单条 add，避免“一条坏导致全批重试刷屏”
          - 对于单条失败：设置短冷却，避免无限重试；不盲目加入 installed
        """
        # 先过滤掉本地已安装
        with self.installed_flows_lock:
            keys_batch = [k for k in keys_batch if k not in self.installed_flows]
        if not keys_batch:
            return

        # 批量构造
        key_list = []
        data_list = []
        entry_triples = []
        for k in keys_batch:
            ip_int, port, proto = unpack_flow_key(k)

            entry_triples.append((ip_int, port, proto))
            # 关键：internal_ip 用字符串，避免类型解释差异导致 match/del 不一致
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

        # 先尝试整批写
        try:
            self.service_table.entry_add(self.target, key_list, data_list)
            with self.installed_flows_lock:
                for k in keys_batch:
                    self.installed_flows.add(k)
            with stats_lock:
                stats["batches_ok"] += 1
                stats["rules_installed"] += len(keys_batch)
            return
        except Exception:
            with stats_lock:
                stats["batches_fail"] += 1

        # 整批失败：退化逐条写，避免重复风暴
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

                with self.installed_flows_lock:
                    self.installed_flows.add(k)
                ok_count += 1

            except Exception:
                # 单条失败：不要立刻反复重试，设置短冷却
                with pending_lock:
                    if len(failed_until) > FAILED_MAX_SIZE:
                        # 粗暴清理一半（足够简单）
                        for kk in list(failed_until.keys())[: len(failed_until) // 2]:
                            failed_until.pop(kk, None)
                    failed_until[k] = now + FAILED_COOLDOWN_SEC
                with stats_lock:
                    stats["adds_fail"] += 1

        if ok_count:
            with stats_lock:
                stats["rules_installed"] += ok_count


def add_pending_keys(controller: Bfrt_GRPC_Client, keys):
    """
    keys: list[int] packed keys（已 parse）
    只做两件事：
      1) 不在 installed 的才考虑
      2) 不在失败冷却窗口的才加入 pending_set（全局唯一去重）
    """
    if not keys:
        return

    now = time.monotonic()
    added = 0

    # 固定加锁顺序：installed -> pending，避免死锁
    with controller.installed_flows_lock:
        with pending_lock:
            for k in keys:
                if k in controller.installed_flows:
                    continue
                until = failed_until.get(k)
                if until is not None and now < until:
                    continue
                pending_set.add(k)
                added += 1

    if added:
        with stats_lock:
            stats["rules_pending_add"] += added


def receiver_and_parse(sock: socket.socket, controller: Bfrt_GRPC_Client):
    """
    简化：直接在 receiver 里 parse + 丢到 pending_set（集合去重）
    保留高效 DGRAM drain + MSG_TRUNC 检测
    """
    sel = selectors.DefaultSelector()
    sock.setblocking(False)
    sel.register(sock, selectors.EVENT_READ)

    buf = bytearray(65536)

    while True:
        sel.select(timeout=1.0)

        while True:
            try:
                nbytes, ancdata, msg_flags, _ = sock.recvmsg_into([buf], 0, socket.MSG_TRUNC)
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
                add_pending_keys(controller, keys)
            else:
                with stats_lock:
                    stats["sock_drop"] += 1


def batcher_simple(controller: Bfrt_GRPC_Client, max_batch=2048, flush_interval=0.01):
    """
    每 flush_interval 把 pending_set swap 出来，按 max_batch 下发
    """
    while True:
        time.sleep(flush_interval)

        with pending_lock:
            if not pending_set:
                continue
            keys = list(pending_set)
            pending_set.clear()

            # 顺便清理过期冷却项（避免 dict 越积越多）
            now = time.monotonic()
            if failed_until:
                # 简单线性清理一部分即可
                for k in list(failed_until.keys())[:5000]:
                    if failed_until.get(k, 0) <= now:
                        failed_until.pop(k, None)

        # 分块下发
        for i in range(0, len(keys), max_batch):
            controller.entry_add_batch(keys[i : i + max_batch])


def cleaner(controller: Bfrt_GRPC_Client, interval=0.2):
    while True:
        controller.idle_entry_batch_clean()
        time.sleep(interval)


def reporter(controller: Bfrt_GRPC_Client, interval=1.0):
    last_rules_in = 0
    last_installed = 0
    last_pending_add = 0
    last_add_fail = 0

    while True:
        time.sleep(interval)

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

        with pending_lock:
            pend_sz = len(pending_set)
            fail_sz = len(failed_until)

        try:
            usage = controller.get_table_usage()
        except Exception:
            usage = -1

        local_num = controller.get_local_flow_entry_num()

        print(
            f"[{datetime.now().strftime('%H:%M:%S')}] "
            f"in/s={rin} pend_add/s={rpend} inst/s={rinst} add_fail/s={add_fail_s} "
            f"pending={pend_sz} fail_cd={fail_sz} local={local_num} usage={usage} "
            f"pkts_ok={s['pkts_ok']} bad={s['pkts_bad']} trunc={s['pkts_trunc']} "
            f"batch_ok={s['batches_ok']} batch_fail={s['batches_fail']} sock_drop={s['sock_drop']}"
        )


def serve_controller(
    sock_path="/tmp/p4_controller.sock",
    rcvbuf_bytes=16 * 1024 * 1024,
    entry_ttl=5000,
    clean_batch_size=1000,
    batch_max=2048,
    batch_flush_interval=0.01,
    clean_interval=0.2,
):
    controller = Bfrt_GRPC_Client(entry_ttl=entry_ttl, clean_batch_size=clean_batch_size)
    controller.clear_service_table()

    if os.path.exists(sock_path):
        os.unlink(sock_path)

    sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    sock.bind(sock_path)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, rcvbuf_bytes)

    threading.Thread(target=receiver_and_parse, args=(sock, controller), daemon=True).start()
    threading.Thread(target=batcher_simple, args=(controller, batch_max, batch_flush_interval), daemon=True).start()
    threading.Thread(target=cleaner, args=(controller, clean_interval), daemon=True).start()
    threading.Thread(target=reporter, args=(controller, 1.0), daemon=True).start()

    while True:
        time.sleep(3600)


if __name__ == "__main__":
    serve_controller(
        sock_path="/tmp/p4_controller.sock",
        entry_ttl=5000,
        clean_batch_size=1000,
        batch_max=2048,
        batch_flush_interval=0.01,
        clean_interval=0.2,
    )
