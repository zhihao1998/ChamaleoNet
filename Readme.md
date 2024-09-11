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


## TODO
- design and execute some benchmarks and stress tests to check the the codebase is solid and measure some performance indicators 
- you can use some trace and replay it 
- do a worst case scenario with sender doing a syn flooding attack
- check malformed packets effects (e.g., using nmap -O option would aready create some funzy packets)
- Do some analysis on the 1h trace we captured some time ago to check timers&dealy, this is used to define timeouts for instance, observe the new flow arrival rate, and the memory usage with a real use case

## Data Plane

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

```



## Benchmarks

### Indicators

#### Packet Counter
- total parsed packet number (log every 100 packets)
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

### Figures

#### timeout v.s. data structure size



## Performance Profile

```bash
sudo valgrind --tool=callgrind --separate-threads=yes --collect-systime=nsec debug/tsdn
sudo rm -rf *.out.*
sudo chmod 777  callgrind.out*
```

## Note

1. Only considers the Ethernet frames.

### Long latency between libpcap timestamp and the time when we get the packet
It's the problem of packet buffer mechanism in Libpcap, which buffers packets for a specific period of time. 

To fix this, if the libpcap on your system has the pcap_set_immediate_mode() function, then:
- use pcap_create() and pcap_activate(), rather than pcap_open_live(), to open the capture device;
- call pcap_set_immediate_mode() between the pcap_create() and pcap_activate() calls.

**Reference:**

- official explanation of the latency: https://www.tcpdump.org/faq.html#q15
- packet buffer timeout of libpcap: https://www.tcpdump.org/manpages/pcap.3pcap.html
- solution: https://stackoverflow.com/questions/36597189/libpcap-delay-between-receiving-frames-and-call-of-callback-function


