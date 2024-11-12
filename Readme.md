# TODO

- replay faster
- how many traffic can be handled with no problem of installing entries
- separate the traffic by incoming and outgoing (only care about the incoming)
- the long-live flow (new packets after deleting the entry in switch)
- install entries by batch rather than single

# C-based Controller for Transparent SDN Honeypot

Source code of the host-based solution of Transparent SDN Honeypot. 

> Use the SDN/programmable switch to design and engineering a system that transforms a “live” network into a darknet/honeypot flexible system. The basic idea is to let the system impersonate an internal host when it is not present (e.g., a laptop or a host that is powered off) so that the traffic received by external hosts (e.g., possible attackers) is rerouted to the darknet/honeypot sensor. To do this, we can opt to use the SDN switch to offload the "intelligence" part of the routing decision.

The logical structure is described as:

![host-flow-diagram.jpg](/.images/host-flow-diagram.jpg)


## Dependencies
This project is developed with the following dependencies:

- tcpdump version 4.9.3
- libpcap version 1.9.1 (with TPACKET_V3)
- gcc (Ubuntu 9.4.0-1ubuntu1~20.04.2) 9.4.0
- GNU Make 4.2.1

## To RUN
1. Create the dirs `make makedir`
2. Specify the device name `dev` to be captured in `tsdn.c`, which is `virbr0` by default.
3. Compile the target ```tsdn```.
4. Run the main executable object by `sudo ./bin/tsdn`. Typically, libpcap requires root privilege. If the current user has root privilege to execute packet capturing, `sudo` can be omitted.
5. Send some packets to the interface.


### Build and Run


```shell
iftofinoup


sudo p4-build -o p4/build/ p4/tf_honeypot.p4

cd p4/log

tfm -p tf_honeypot

p4 -p tf_honeypot

sudo tcpdump -vvv -i veth2 -w pcap/test.pcap

sudo tcpreplay -i veth4 trace/ip_complete.pcap

```




## Add virtual interface

```bash
sudo brctl addbr brtest
sudo ifconfig brtest up
```

```bash
sudo bridge fdb add 52:54:00:50:f6:6f dev vnet2 master temp
sudo bridge fdb add 90:2d:77:3f:b5:a2 dev ens5f1 master temp

sudo bridge fdb del 52:54:00:50:f6:6f dev vnet2 master temp
sudo bridge fdb del 90:2d:77:3f:b5:a2 dev ens5f1 master temp

sudo bridge fdb del 52:54:00:50:f6:6f dev vnet84 master temp
sudo bridge fdb del 90:2d:77:3f:b5:a2 dev ens5f1v3 master temp

sudo bridge fdb del 90:2d:77:3f:b5:a2 dev vnet14 master temp
```

```bash
 sudo brctl show br1
sudo brctl showmacs br1
sudo brctl showstp br1

nmcli connection show --active
```

## Attack Simulation

### SYN Flood

```bash
sudo tcpreplay -i veth250 --mbps 1000 trace/syn_flood.pcap
```

```bash
sudo tcpreplay-edit --enet-dmac=90:2d:77:3f:b5:a2 -i ens5f1 --stats=2 --mtu-trunc --mbps=1000 polito_with_syn_flood.pcap

sudo tcpreplay-edit -i enp8s0 --stats=5 --mtu-trunc --mbps=1000 trace/polito_with_syn_flood.pcap

sudo tcpreplay-edit --enet-dmac=90:2d:77:3f:b5:a2 --enet-smac=52:54:00:16:f4:4c -i enp8s0 --stats=2 --mtu-trunc --mbps=2000 trace/polito_with_syn_flood.pcap

trafgen --cpp --dev enp8s0 --conf trace/syn_flood.traf -n 10000000 --verbose -b 5Gbit

tcprewrite --enet-dmac=90:2d:77:3f:b5:a2 --enet-smac=52:54:00:16:f4:4c --fixlen=pad --infile=polito-1m_00000_20240510092043.pcap --outfile=out_polito_1m.pcap

```


## Benchmarks

### Indicators

#### Packet Counter

- total parsed packet number
- TCP packet number
- UDP packet number
- ICMP packet number

#### Data Structure

- hash table size
- circular buffer size
- lazy free buffer size
- all free list size in use
- all free list size in total

#### Functionalities

- installed flow number (returned by the grpc client)
- expired packet number


## Performance Profile

### Memory Usage Monitoring

valgrind degrades the performance of the target program a lot, so do the memory usage profiling separately.

```bash
sudo valgrind --tool=massif ./debug/tsdn
```

```bash
sudo valgrind --tool=callgrind --collect-systime=nsec debug/tsdn
sudo rm -rf *.out.*
sudo chmod 777  callgrind.out*
```

### Traffic Monitoring

Once the response of one request packet is received, it will be identified as a flow originated or destined to an active service, which is very possible a legitimate flow. The controller installs an entry to the switch to drop all packets from this flow, alleviating the traffic load that it has to process. Here we monitor the traffic speed of the interface that receives traffic from switch, to evaluate how many legitimate flow can be filtered.

```bash
vnstat --live -i enp8s0  --json > log/recv_speed_log.json

vnstat --live -i enp8s0  --json > log/send_speed_log.json
```


### Utils

Split a large pcap file into several smaller ones.

```bash
tcpdump -r polito-1h-10-05-2024-snaplen-100-echelon3.pcap -w ~/Tstat/data/pcap_1s/polito-1s- -G 1

scp net_stat.csv zhihaow@restsrv01-smartdata01:/home/zhihaow/codes/honeypot_c_controller/log
```
