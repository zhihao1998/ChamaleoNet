from scapy.sendrecv import sendp
from scapy.all import conf
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether

l2_socket = conf.L2socket(iface='docker0')

for i in range(20):
    a = i // 10000
    b = (i % 10000) // 100
    c = i % 100
    ip_src = f"10.{a}.{b}.{c}"
    pkt_raw = Ether()/IP(src=ip_src, dst="10.255.255.255")/TCP(sport=1,dport=2,flags="S")
    sendp(pkt_raw, socket=l2_socket, verbose=False)