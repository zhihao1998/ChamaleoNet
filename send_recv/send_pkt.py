from scapy.sendrecv import sendp
from scapy.all import conf
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
import random
import time

l2_socket = conf.L2socket(iface='veth250')

for i in range(5):
    a = random.randint(0, 255)
    b = random.randint(0, 255)
    c = random.randint(0, 255)

    ip_src = f"10.{a}.{b}.{c}"
    payload = "a"*6000
    tot_len = 14 + 20 + 20 + len(payload)
    pkt_raw = Ether()/IP(src=ip_src, dst="10.233.233.233", len=tot_len)/TCP(sport=1,dport=2)/payload
    print(pkt_raw.summary(), len(pkt_raw))
    print(pkt_raw[IP].show())
    sendp(pkt_raw, socket=l2_socket, verbose=False)
    time.sleep(0.2)

    # pkt_raw = Ether()/IP(src="10.233.233.233", dst="10.0.0.10")/TCP(sport=2,dport=1,flags="SA")
    # sendp(pkt_raw, socket=l2_socket, verbose=False)