# TODO

- some problem with size of circular buffer
- throughput
- the long-live flow (new packets after deleting the entry in switch)

# C-based Controller for Transparent SDN Honeypot

Source code of the host-based solution of Transparent SDN Honeypot. 

> Use the SDN/programmable switch to design and engineering a system that transforms a “live” network into a darknet/honeypot flexible system. The basic idea is to let the system impersonate an internal host when it is not present (e.g., a laptop or a host that is powered off) so that the traffic received by external hosts (e.g., possible attackers) is rerouted to the darknet/honeypot sensor. To do this, we can opt to use the SDN switch to offload the "intelligence" part of the routing decision.

The logical structure is described as:

![host-flow-diagram.jpg](/.images/host-flow-diagram.jpg)

## Features

- Three levels of TIMEOUT (100ms, 50ms, 20ms)

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
sudo brctl addbr virbr0
sudo brctl addbr virbr1
sudo ifconfig virbr0 up
sudo ifconfig virbr1 up
```

## Attack Simulation

### SYN Flood

```bash
sudo tcpreplay -i veth250 --mbps 1000 trace/syn_flood.pcap
```

```bash
sudo tcpreplay-edit --enet-dmac=90:2d:77:3f:b5:a2 -i enp8s0 --stats=5 --mtu-trunc --mbps=1000 trace/polito_with_syn_flood.pcap
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
vnstat --live -i enp8s0  --json > log/speed_log.json
```