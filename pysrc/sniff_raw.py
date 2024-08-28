#coding=utf-8
from scapy.all import *
now_time = datetime.now().strftime( "%Y%m%d%H%M%S" )
filename = "../pcap/{0}.pcap".format(now_time)


o_open_file= PcapWriter(filename, append=True)
def callback(packet):
    packet.show()
    o_open_file.write(packet)
   
dpkt_input = sniff(iface = "virbr0",  filter='tcp',prn = callback)