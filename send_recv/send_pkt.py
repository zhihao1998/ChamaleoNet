from scapy.sendrecv import sendp
from scapy.all import conf
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
import random
import time

l2_socket = conf.L2socket(iface='enp10s0')

for i in range(100):
    a = random.randint(0, 255)
    b = random.randint(0, 255)
    c = random.randint(0, 255)

    src_mac = "52:54:00:5b:57:5c"
    # dst_mac = "90:2d:77:3f:b5:a2"
    # dst_mac="52:54:00:fa:1c:6d"
    # dst_mac = "7a:27:46:46:ae:94"
    # dst_mac="b2:b0:fc:63:fb:7d"
    dst_mac = "ff:ff:ff:ff:ff:ff"

    ip_src = f"10.{a}.{b}.{c}"
    payload = "a"*60
    tot_len = 14 + 20 + 20 + len(payload)
    pkt_raw = Ether(src=src_mac, dst=dst_mac)/IP(src=ip_src, dst="10.233.233.233")/TCP(sport=1,dport=2)/payload
    print(pkt_raw.show())
    sendp(pkt_raw, socket=l2_socket, verbose=False)
    # time.sleep(0.2)

    # pkt_raw = Ether()/IP(src="10.233.233.233", dst="10.0.0.10")/TCP(sport=2,dport=1,flags="SA")
    # sendp(pkt_raw, socket=l2_socket, verbose=False)