import argparse
from trex_stl_lib.api import *

DST_MAC = "90:2d:77:3f:b5:a2"
SRC_IP   = "16.0.0.10"
SRC_PORT = 12345
PKT_SIZE = 60

def pad(pkt):
        pad_len = max(0, PKT_SIZE - len(pkt))
        return pkt / Raw(load=b"x" * pad_len) if pad_len > 0 else pkt


def vm_rand_dst_ip_and_dport(l4: str):
    """
    l4: "TCP" or "UDP"
    Random dst ip: 130.192.0.1 - 130.192.255.254
    Random dst port: 1 - 65535
    """
    vm = STLVM()

    vm.var(name="ip_dst", min_value="130.192.0.1", max_value="130.192.255.254",
        size=4, op="random")
    vm.write(fv_name="ip_dst", pkt_offset="IP.dst")

    vm.var(name="dport", min_value=1, max_value=65535, size=2, op="random")
    vm.write(fv_name="dport", pkt_offset=f"{l4}.dport")

    # Last: fix IP + L4 checksums
    vm.fix_chksum()
    return vm


def vm_rand_dst_ip_only():
    """ICMP has no ports; randomize dst ip only."""
    vm = STLVM()
    vm.var(name="ip_dst", min_value="130.192.0.1", max_value="130.192.255.254",
        size=4, op="random")
    vm.write(fv_name="ip_dst", pkt_offset="IP.dst")
    vm.fix_chksum()
    return vm


def tcp_stream():
    base = (
        Ether(dst=DST_MAC) /
        IP(src=SRC_IP) /
        TCP(sport=SRC_PORT, dport=80, flags="S")  # dport overwritten by VM; value here ignored
    )
    return STLStream(
        packet=STLPktBuilder(pkt=pad(base), vm=vm_rand_dst_ip_and_dport("TCP")),
        mode=STLTXCont(),
    )


def udp_stream():
    base = (
        Ether(dst=DST_MAC) /
        IP(src=SRC_IP) /
        UDP(sport=SRC_PORT, dport=53)  # dport overwritten by VM
    )
    return STLStream(
        packet=STLPktBuilder(pkt=pad(base), vm=vm_rand_dst_ip_and_dport("UDP")),
        mode=STLTXCont(),
    )


def icmp_stream():
    base = (
        Ether(dst=DST_MAC) /
        IP(src=SRC_IP) /
        ICMP(type=8, code=0)  # echo request
    )
    return STLStream(
        packet=STLPktBuilder(pkt=pad(base), vm=vm_rand_dst_ip_only()),
        mode=STLTXCont(),
    )

class STLS1(object):
    """TCP SYN flood"""

    def get_streams(self, tunables, **kwargs):
        argparse.ArgumentParser().parse_args(tunables)
        # These streams are mixed; change pps to tune the blend
        return [
            tcp_stream(),
            udp_stream(),
            icmp_stream(),
        ]


def register():
    return STLS1()
