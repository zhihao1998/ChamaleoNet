import argparse
from trex_stl_lib.api import *

# ====== Edit for your environment ======
DST_MAC_P0 = "90:2d:77:3f:b5:a2"   # dst MAC on port0 egress
DST_MAC_P1 = "90:2d:77:3f:b5:a2"   # dst MAC on port1 egress

CLIENT_IP = "16.0.0.10"            # fixed client IP
SERVER_IP_MIN = "130.192.0.1"
SERVER_IP_MAX = "130.192.255.254"

PKT_SIZE = 60

def pad(pkt, pkt_size=PKT_SIZE):
    pad_len = max(0, pkt_size - len(pkt))
    return pkt / Raw(load=b"x" * pad_len) if pad_len > 0 else pkt


# --------- UDP / TCP: tuple_var for reproducible 1:1 request/reply pairing ---------
def vm_tuple_req(l4: str):
    vm = STLVM()
    vm.tuple_var(
        name="t",
        ip_min=SERVER_IP_MIN, ip_max=SERVER_IP_MAX,
        port_min=1, port_max=65535,
    )
    vm.write("t.ip", "IP.dst")
    vm.write("t.port", f"{l4}.dport")
    vm.fix_chksum()
    return vm


def vm_tuple_rsp(l4: str):
    vm = STLVM()
    vm.tuple_var(
        name="t",
        ip_min=SERVER_IP_MIN, ip_max=SERVER_IP_MAX,
        port_min=1, port_max=65535,
    )
    # reply: server -> client
    vm.write("t.ip", "IP.src")
    vm.write("t.port", f"{l4}.sport")

    vm.var(name="client_ip", min_value=CLIENT_IP, max_value=CLIENT_IP, size=4, op="inc")
    vm.write("client_ip", "IP.dst")

    vm.fix_chksum()
    return vm


# --------- ICMP: random server IP + inc id/seq (same start on both ends for pairing) ---------
def vm_icmp_req():
    vm = STLVM()
    vm.var(name="ip_dst", min_value=SERVER_IP_MIN, max_value=SERVER_IP_MAX, size=4, op="inc")
    vm.write("ip_dst", "IP.dst")

    vm.var(name="icmp_id",  min_value=1, max_value=65535, size=2, op="inc")
    vm.var(name="icmp_seq", min_value=1, max_value=65535, size=2, op="inc")
    vm.write("icmp_id",  "ICMP.id")
    vm.write("icmp_seq", "ICMP.seq")

    vm.fix_chksum()
    return vm


def vm_icmp_rsp():
    vm = STLVM()
    # Align reply src with request dst (same inc sequence)
    vm.var(name="ip_src", min_value=SERVER_IP_MIN, max_value=SERVER_IP_MAX, size=4, op="inc")
    vm.write("ip_src", "IP.src")

    vm.var(name="client_ip", min_value=CLIENT_IP, max_value=CLIENT_IP, size=4, op="inc")
    vm.write("client_ip", "IP.dst")

    vm.var(name="icmp_id",  min_value=1, max_value=65535, size=2, op="inc")
    vm.var(name="icmp_seq", min_value=1, max_value=65535, size=2, op="inc")
    vm.write("icmp_id",  "ICMP.id")
    vm.write("icmp_seq", "ICMP.seq")

    vm.fix_chksum()
    return vm


# --------- Streams（short-lived：SingleBurst） ---------
def udp_req():
    base = Ether(dst=DST_MAC_P0) / IP(src=CLIENT_IP) / UDP(sport=12345, dport=53) / Raw(load=b"Q")
    return STLStream(packet=STLPktBuilder(pkt=pad(base), vm=vm_tuple_req("UDP")),
                     mode=STLTXCont(),
                     name="udp_req")


def udp_rsp():
    base = Ether(dst=DST_MAC_P1) / IP(dst=CLIENT_IP) / UDP(sport=53, dport=12345) / Raw(load=b"R")
    return STLStream(packet=STLPktBuilder(pkt=pad(base), vm=vm_tuple_rsp("UDP")),
                     mode=STLTXCont(),
                     name="udp_rsp")


def tcp_syn_req():
    base = Ether(dst=DST_MAC_P0) / IP(src=CLIENT_IP) / TCP(sport=12345, dport=80, flags="S", seq=1000)
    return STLStream(packet=STLPktBuilder(pkt=pad(base), vm=vm_tuple_req("TCP")),
                     mode=STLTXCont(),
                     name="tcp_syn_req")


def tcp_synack_rsp():
    base = Ether(dst=DST_MAC_P1) / IP(dst=CLIENT_IP) / TCP(sport=80, dport=12345, flags="SA", seq=2000, ack=1001)
    return STLStream(packet=STLPktBuilder(pkt=pad(base), vm=vm_tuple_rsp("TCP")),
                     mode=STLTXCont(),
                     name="tcp_synack_rsp")


def icmp_req():
    base = Ether(dst=DST_MAC_P0) / IP(src=CLIENT_IP) / ICMP(type=8, code=0)  # echo request
    return STLStream(packet=STLPktBuilder(pkt=pad(base), vm=vm_icmp_req()),
                     mode=STLTXCont(),
                     name="icmp_req")


def icmp_rsp():
    base = Ether(dst=DST_MAC_P1) / IP(dst=CLIENT_IP) / ICMP(type=0, code=0)  # echo reply
    return STLStream(packet=STLPktBuilder(pkt=pad(base), vm=vm_icmp_rsp()),
                     mode=STLTXCont(),
                     name="icmp_rsp")


class STLS1(object):
    def get_streams(self, tunables, **kwargs):
        parser = argparse.ArgumentParser("Mixed short-lived flows: UDP+TCP+ICMP, each 1req+1rsp")

        args = parser.parse_args(tunables)

        port_id = kwargs.get("port_id", 0)

        if port_id == 0:
            # client port: send requests (UDP+TCP+ICMP mixed)
            return [
                udp_req(),
                tcp_syn_req(),
                icmp_req(),
            ]
        else:
            # server port: send replies
            return [
                udp_rsp(),
                tcp_synack_rsp(),
                icmp_rsp(),
            ]


def register():
    return STLS1()
