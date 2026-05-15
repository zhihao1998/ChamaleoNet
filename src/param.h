#pragma once

/* Experiments */
// #define MAX_CAPTURE_PKTS 50000000
#define FLOW_HASH_MEASURE
// #define PKT_PROCESS_TIME_MEASURE
// #define SWITCH_ENABLED

/* maximum number of concurrent TCP connection stored in the vector TTP 
Increase this number on high speed network will help ...*/
#define PKT_BUF_SIZE 400000

/* Define granularity of garbage collection splitting. 
 The flow table is not scanned in one time,
 but the workload is done in PKT_BUF_GC_SPLIT_SIZE times
 IMPORTANT: it must be a divisor of PKT_BUF_GC_PERIOD,
 PKT_BUF_SIZE and MAX_UDP_PAIRS  */

/* Each time the garbage collection is fired, it scans PKT_BUF_GC_SPLIT_SIZE tcp flows */
#define PKT_BUF_GC_SPLIT_SIZE 10
// #define CIRC_GC_SPLIT_SIZE 1000

/* Define how often garbage collection scans the whole flow table,  
 * i.e. very PKT_BUF_GC_PERIOD * (PKT_BUF_SIZE / PKT_BUF_GC_SPLIT_SIZE) microseconds
*/
#define PKT_BUF_GC_PERIOD 10

/* TIMEOUT in microseconds: timeout to consider a packet is expired (no answering from internal hosts) */
#define PKT_TIMEOUT 1000000

/* max depth of the linear search in the previous vector... */
#define LIST_SEARCH_DEPT 100


/* connection records are stored in a hash table.  Buckets are linked	*/
/* lists sorted by most recent access.					*/
/* oughta be prime  and larger than PKT_BUF_SIZE */

/* Every FLOW_HASH_TABLE_GC_PERIOD, scan FLOW_HASH_TABLE_GC_SIZE entries. */
/* After FLOW_HASH_TABLE_GC_PERIOD / (FLOW_HASH_TABLE_SIZE / FLOW_HASH_TABLE_GC_SIZE), the whole hash table is completely scanned once */
/* So the lazy free timeout should be 2*FLOW_HASH_TABLE_GC_PERIOD / (FLOW_HASH_TABLE_SIZE / FLOW_HASH_TABLE_GC_SIZE) */
#define FLOW_HASH_TABLE_SIZE 1000000
#define FLOW_HASH_TABLE_GC_SIZE 10
#define FLOW_HASH_TABLE_GC_PERIOD 10
#define FLOW_HASH_TABLE_GC_TIMEOUT 1000000

/* 
* Switch GRPC Client 
*/

/* size of the circular buffer of the pending entry list to be installed */
#define ENTRY_BUF_SIZE 1000000

/* polling time for checking the idle entries in P4 tables */
#define ENTRY_INSTALL_BATCH_SIZE 900
#define ENTRY_IDLE_TIMEOUT 10000 //ms
#define ENTRY_IDLE_CLEAN_BATCH_SIZE 2000
#define ENTRY_GC_PERIOD 5000000 //us

/* Max number of nets to check if ip is internal or external */
#define MAX_INTERNAL_HOSTS  100


/* Interfaces to capture and send packets */
// #define RECV_INTF "enp10s0"


/* Logging Sampling granularity
 * Wall-clock stats/status (.status file + stats CSV) interval is driven at runtime by
 * TSDN_STATS_LOG_SAMPLE_US (see tsdn.c). Optional presets: TSDN_LOG_OUTPUT_MODE=debug|daemon
 * at the end of conf/controller.env (sourced as shell).
 */
#define DO_STATS
#define LOG_TO_FILE
#define PKT_LOG_SAMPLE_CNT 10000      // pkt_count
#define TIMEOUT_SAMPLE_CNT 100000     // tot_expired_pkt_count
#define STATS_LOG_SAMPLE_TIME 1000000  // us (compile-time default; runtime env overrides)

/* pcap idle wake-up period (ms), used to run timeout GC when no packets arrive */
#define PCAP_IDLE_TICK_MS 20

/* ================== Packet Egress (runtime only; no compile-time defaults) ==================
 * Collector and switch *destination* MACs must come from the environment (set
 * by tsdn-multi.sh from conf/tsdn.interfaces), or tsdn exits at startup.
 * MACs are static: set in conf/tsdn.interfaces (collector / switch_dst lines) or via
 * TSDN_COLLECTOR_DST_MAC / TSDN_SWITCH_DST_MAC in conf/controller.env; the binary only reads env.
 *   TSDN_COLLECTOR_INTF       — raw socket for packets to the collector
 *   TSDN_COLLECTOR_SRC_MAC    — optional source MAC override for collector egress
 *   TSDN_COLLECTOR_DST_MAC    — aa:bb:cc:dd:ee:ff (or hyphen-separated)
 *   TSDN_SWITCH_DST_MAC       — next-hop Ethernet MAC toward the P4 switch
 * Switch egress *interface* is always the capture interface (argv[1]), source MAC is read from that iface.
 * Collector egress source MAC defaults to SIOCGIFHWADDR on TSDN_COLLECTOR_INTF, then optional override applies.
 */
