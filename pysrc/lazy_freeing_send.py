from scapy.sendrecv import sendp
from scapy.all import conf
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
import time
import random

for i in range(1,10):
    sendp(Ether()/IP(src="10.0.0."+str(i), dst="10.0.0.254")/TCP(sport=1,dport=2,flags="S")/str(i), iface="virbr0")

random.seed(41)

rand_ips = set([random.randint(1,9) for i in range(5)])

print("sending some response packets")

for ip in rand_ips:
    sendp(Ether()/IP(src="10.0.0.254",dst=f"10.0.0.{ip}")/TCP(sport=2,dport=1)/str(ip),iface="virbr0")

print("sending again to test lazy freeing")

for ip in rand_ips:
    sendp(Ether()/IP(src="10.0.0.254",dst=f"10.0.0.{ip}")/TCP(sport=2,dport=1)/str(ip),iface="virbr0")

for ip in rand_ips:
    sendp(Ether()/IP(src="10.0.0.254",dst=f"10.0.0.{ip}")/TCP(sport=2,dport=1)/str(ip),iface="virbr0")