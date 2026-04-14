<div align="center">
<h1><span style="font-variant: small-caps;">ChamaleoNet</span>: Programmable Passive Probe for Enhanced Visibility on Erroneous Traffic</h1>

[🤖Overview](#🤖overview) | 
[📦Deployment](#📦deployment) | 
[📚Cite](#📚cite)

[![ArXiv Link](https://img.shields.io/badge/arXiv-2508.12496-red?logo=arxiv)](https://arxiv.org/abs/2508.12496)

</div>

<h2 id="🤖overview">🤖 Overview</h2>

![alt text](./assets/live_deployment.jpg)

<span style="font-variant: small-caps;">ChamaleoNet</span> is an open-source system that brings visibility into *erroneous traffic* — network requests that go unanswered or generate errors. Unlike traditional monitoring tools that focus on performance metrics, security logs, or unsolicited traffic (e.g., network telescopes), <span style="font-variant: small-caps;">ChamaleoNet</span> highlights an overlooked but critical signal:

- clients connecting to offline or firewalled systems
- misconfigured hosts targeting the wrong servers
- routing issues
- malicious actors probing for vulnerable services.

By capturing and analyzing this class of traffic, <span style="font-variant: small-caps;">ChamaleoNet</span> helps administrators uncover misconfigurations, detect infected internal hosts, and observe external scans more effectively.

This is the code repository for the paper [ChamaleoNet: Programmable Passive Probe for Enhanced Visibility on Erroneous Traffic](https://arxiv.org/), which is under review at IEEE Transactions on Networking.

### ✨ Key Features

- **Erroneous traffic monitoring**: Collects packets that normal systems ignore, offering a new lens into failures, misconfigurations, and attacks.
- **Visibility on external/internal radiation**: Logs radiation from both external hosts (e.g., scans against inactive or firewalled systems) and internal hosts (e.g., misconfigured or compromised devices).
- **Impersonator support**: Can support impersonating inactive hosts or services, engaging scanners like a honeypot.
- **SDN-powered scalability**: Built on programmable switches, filtering are offloaded to the high-speed programmable switches.
- **Privacy by design**: Collects only erroneous packets, strips application payloads, and anonymizes internal IPs where possible.

### 🚀 Why <span style="font-variant: small-caps;">ChamaleoNet</span>?

Traditional monitoring systems:

✅ provide stats on normal traffic (performance, usage),

✅ protect infrastructure against known threats,

✅ log unsolicited traffic on unused subnets (telescopes),

❌ but miss erroneous traffic — a valuable signal for both operations and security.

<span style="font-variant: small-caps;">ChamaleoNet</span> fills this gap by transforming any campus or enterprise network into a flexible, transparent monitor for erroneous traffic, without interfering with regular operations.

<h2 id="📦deployment">📦 Deployment</h2>

### Requirements

#### Hardware requirements

As shown in the figure above,  <span style="font-variant: small-caps;">ChamaleoNet</span>  depends on a programmable switch (e.g., we use P4-based [Intel Tofino](https://www.intel.com/content/www/us/en/products/network-io/programmable-ethernet-switch.html)) and a server hosting the control plane and FSD-NF. There should be a dedicated port on the switch connected to the server, serving as data path. Control path requires a connection to the switch via gRPC. The collector can either be hosted at the same server or a dedicated server connected to the FSD-NF.

#### Software requirements

- gcc compiler
- Libpcap
- P4 compiler (tofino-p4c)
- Python 3.x
- libpython3-dev
- BFrt gRPC client library

### Build

To install <span style="font-variant: small-caps;">ChamaleoNet</span>, follow:

1. **Configuration**

- Edit the `conf/net.internal` and `conf/net.responder` files to specify the subnets to monitor.
- Edit the `src/param.h` file to set the parameters for the FSD-NF, such as sizing the data structures, and tuning hash-table behaviour.
- **Multiple capture ports (optional):** copy `conf/tsdn.interfaces.example` to `conf/tsdn.interfaces` and list the Linux interface names (one per line, or space-separated on a line; `#` starts a comment). This file is used by `tsdn-multi.sh` when starting one `tsdn` process per NIC. Override the path with the environment variable `TSDN_INTERFACES_FILE` if needed.
- Edit the `p4_src/p4include/definition.p4` and `p4_src/bfrt_setup.py` to set P4-side parameters, such as the switch local port number, and target IP ranges.

2. **Compile and start P4 program**

```bash
<your p4 build cmd> p4_src/tf_honeypot.p4
<your p4 start cmd> -p tf_honeypot # Start the P4 program and enter the BFrt shell

bfshell> bfrt_python p4_src/bfrt_setup.py false # Set up the tables and ports on the switch
``` 

3. **Compile and start the FSD-NF**

Single capture interface (`tsdn` takes the NIC name as the first argument; root required for live capture):

```bash
make
sudo ./bin/tsdn <interface>
```

**Multiple interfaces:** use `tsdn-multi.sh` so the project is built once and one `tsdn` process is started per interface. Each `./tsdn-multi.sh start` creates a time-stamped run directory `log/runs/YYYYMMDD_HH-MM-SS/` containing statistics CSVs (`<iface>_pid….csv`) and per-NIC logs under `tsdn/<iface>.log`. The same directory also holds **`tsdn/<iface>.status`**: a one-line snapshot updated on the same schedule as statistics sampling (`STATS_LOG_SAMPLE_TIME` in `src/param.h`, default 1s). A symlink `log/runs/latest` points at the most recent run (used by `follow` / `watch` / `status`). By default each NIC is brought up (`sudo ifconfig <iface> up`) before `sudo env TSDN_LOG_RUN_DIR=… ./bin/tsdn <iface>` so all instances share the same run directory.

**Live metrics (multi-NIC):** each process writes the same column layout to `tsdn/<iface>.status` and to stderr. **If stderr is a TTY** (e.g. `sudo ./bin/tsdn eth0` in a terminal), a **fixed table header** is printed once and only the **data row** is redrawn each sample. **If stderr is not a TTY** (e.g. `tsdn-multi.sh start` redirecting to `*.log`), each sample is one plain-text line with a `[iface]` prefix.

Column meanings (see also comments above `tsdn_emit_status_line` in `src/tsdn.c`):

- **pcap_rx / pcap_drop / pcap_ifdrop:** From `pcap_stats()` when the implementation reports non-zero `ps_recv`. On **Linux with TPACKET/mmap**, `pcap_stats()` often returns **0** for recv/drop even though traffic is flowing; in that case the program **falls back** to totals from `getsockopt(PACKET_STATISTICS)` on the capture socket (documented in `print_all_stats` and the status line source).
- **pkt_pps:** Smoothed **processed** packet rate: `pkt_count` delta divided by wall time between status samples (see `STATS_LOG_SAMPLE_TIME`).
- **pcap_pend:** `pcap_recv − pkt_count` — uses the **same merged recv** as `pcap_rx` (libpcap or `PACKET_STATISTICS` fallback) minus packets your loop has counted in `pkt_count`; an **accounting / backlog gap inside the capture path**, not the same as sysfs NIC counters.
- **bloom_rsp:** `bloom_rule_sending_count_tot` — **response-direction (S2C) packets** that hit the bloom / `SendPktSwitch` path (flows that need bloom-side handling).
- **nic_drx:** increase in `/sys/class/net/<iface>/statistics/rx_packets` since the **last** status sample — **NIC/stack receive volume for that interval** (Linux does not expose a portable “current RX ring length” for all drivers).
- **nic_oob_d:** increase in a driver **ethtool** statistic when one is found (names like `rx_out_of_buffer`, `rx_alloc_fail`, …) — **buffer / OOB pressure** at the driver; `-` if the NIC does not expose a matching counter. This is still not the same as `pcap_pend`.
- **ruleq:** depth of the rule-install queue (packet thread → install thread).

**Single interface:** if `TSDN_LOG_RUN_DIR` is unset, CSV logs go to `log/runs/YYYYMMDD_HH-MM-SS/` automatically (one folder per process start time).

```bash
cp conf/tsdn.interfaces.example conf/tsdn.interfaces   # once; then edit the list
./tsdn-multi.sh list # optional: show which interfaces will be used
./tsdn-multi.sh start   # no arguments: read conf/tsdn.interfaces
./tsdn-multi.sh follow  # optional: tail -F all per-iface logs in one terminal
./tsdn-multi.sh watch   # optional: watch(1) refreshes all tsdn/<iface>.status lines (needs procps)
./tsdn-multi.sh stop    # stop every tsdn from this checkout
```

To pass interfaces explicitly instead of the config file: `./tsdn-multi.sh start enp10s0 enp11s0 ...`. Optional environment variables: `TSDN_MAKE_CLEAN=1` (full rebuild before start), `TSDN_SKIP_MAKE=1` (skip `make`), `TSDN_SKIP_IFUP=1` (skip `ifconfig up`), `TSDN_WATCH_INTERVAL` (seconds between `watch` refreshes, default `1`). If `watch` is not installed, use e.g. `tail -F log/runs/latest/tsdn/*.status`.

4. **Start the packet collection**

```bash
tcpdump -i <interface> -w <output_file>
```

### Project Structure

```bash
├── src
│   ├── bfrt_grpc.c # Interface to the Python-based BFrt controller
│   ├── data_structure.c # Data structures for packet handling
│   ├── ip.c # Utilities for IP address handling
│   ├── log.c # Logging utilities
│   ├── param.h # Configuration parameters
│   ├── pkt_handle.c # Packet handling logic
│   ├── struct.h # Header file for data structures
│   ├── tsdn.c # Main logic for the project
│   ├── tsdn.h # Header file for main logic
│   └── utils.c # Utility functions
├── bfrt_grpc
│   ├── bfrt_grpc_client.py # Python client for BFrt gRPC
├── conf
│   ├── net.internal # Subnets to be monitored
│   ├── net.responder # Subnets to skip buffering
│   ├── tsdn.interfaces.example # Template: NIC list for tsdn-multi.sh
│   └── tsdn.interfaces # Local copy (optional): actual NIC list; not in git by default
├── tsdn-multi.sh # Start/stop many tsdn instances; logs and *.status under log/runs/<run>/tsdn/
├── LICENSE
├── Makefile # Makefile for building the project
├── p4_src # P4 source files for the programmable switch
│   ├── p4include
│   │   ├── definition.p4
│   │   ├── egress.p4
│   │   ├── header.p4
│   │   └── ingress.p4
│   ├── tf_honeypot.p4 # P4 program for the honeypot functionality
│   └── bfrt_setup.py # set up the tables and ports on the switch
```

<h2 id="📚cite">📚 Cite</h2>

```bibtex
@misc{wang2025chamaleonet,
      title={ChamaleoNet: Programmable Passive Probe for Enhanced Visibility on Erroneous Traffic}, 
      author={Zhihao Wang and Alessandro Cornacchia and Andrea Bianco and Idilio Drago and Paolo Giaccone and Dingde Jiang and Marco Mellia},
      year={2025},
      eprint={2508.12496},
      archivePrefix={arXiv},
      primaryClass={cs.CR},
      url={https://arxiv.org/abs/2508.12496}, 
}
```

# Acknowledgement

The network infrastructure used in this work was supported by the [SUP4RNET](https://sup4rnet.github.io/) at Politecnico di Torino, Italy. Thanks to all authors for their contributions to <span style="font-variant: small-caps;">ChamaleoNet</span>.


# Licence

Licensed under the MIT license.