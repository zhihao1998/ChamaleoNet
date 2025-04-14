
/* maximum number of concurrent TCP connection stored in the vector TTP 
Increase this number on high speed network will help ...*/
#define PKT_BUF_SIZE 10000

/* Define granularity of garbage collection splitting. 
 The flow table is not scanned in one time,
 but the workload is done in PKT_BUF_GC_SPLIT_SIZE times
 IMPORTANT: it must be a divisor of PKT_BUF_GC_PERIOD,
 PKT_BUF_SIZE and MAX_UDP_PAIRS  */

/* Each time the garbage collection is fired, it scans PKT_BUF_GC_SPLIT_SIZE tcp flows */
#define PKT_BUF_GC_SPLIT_SIZE 100
// #define CIRC_GC_SPLIT_SIZE 1000

/* Define how often garbage collection scans the whole flow table,  
 * i.e. very PKT_BUF_GC_PERIOD * (PKT_BUF_SIZE / PKT_BUF_GC_SPLIT_SIZE) microseconds
*/
#define PKT_BUF_GC_PERIOD 100

/* TIMEOUT in microseconds: timeout to consider a packet is expired (no answering from internal hosts) */
#define PKT_TIMEOUT 70000

/* max depth of the linear search in the previous vector... */
#define LIST_SEARCH_DEPT 5

/* connection records are stored in a hash table.  Buckets are linked	*/
/* lists sorted by most recent access.					*/
/* oughta be prime  and larger than PKT_BUF_SIZE */
#define FLOW_HASH_TABLE_SIZE 1000000

/* Every FLOW_HASH_TABLE_GC_PERIOD, scan FLOW_HASH_TABLE_GC_SIZE entries. */
/* After FLOW_HASH_TABLE_GC_PERIOD / (FLOW_HASH_TABLE_SIZE / FLOW_HASH_TABLE_GC_SIZE), the whole hash table is completely scanned once */
/* So the lazy free timeout should be 2*FLOW_HASH_TABLE_GC_PERIOD / (FLOW_HASH_TABLE_SIZE / FLOW_HASH_TABLE_GC_SIZE) */
#define FLOW_HASH_TABLE_GC_SIZE 1000
#define FLOW_HASH_TABLE_GC_PERIOD 1000
#define FLOW_HASH_TABLE_GC_TIMEOUT 1000000

/* 
* Switch GRPC Client 
*/

/* size of the circular buffer of the pending entry list to be installed */
#define ENTRY_BUF_SIZE 1000000

/* polling time for checking the idle entries in P4 tables */
#define ENTRY_INSTALL_BATCH_SIZE 2000
#define ENTRY_IDLE_TIMEOUT 10000 //ms
#define ENTRY_IDLE_CLEAN_BATCH_SIZE 2000
#define ENTRY_GC_PERIOD 5000000 //us

/* Max number of nets to check if ip is internal or external */
#define MAX_INTERNAL_HOSTS  100


/* Interfaces to capture and send packets */
#define RECV_INTF "enp10s0"


/* Logging Sampling granularity */
#define DO_STATS
#define LOG_TO_FILE
#define PKT_LOG_SAMPLE_CNT 500000      // pkt_count
#define TIMEOUT_SAMPLE_CNT 500000     // tot_expired_pkt_count
#define STATS_LOG_SAMPLE_TIME 60000000  // us

#define SWITCH_ENABLED

/* Send to the SR-IOV VF interface */
#define SEND_INTF "enp9s0"
#define COLLECTOR_DEST_MAC_0 0x52
#define COLLECTOR_DEST_MAC_1 0x54
#define COLLECTOR_DEST_MAC_2 0x00
#define COLLECTOR_DEST_MAC_3 0x6a
#define COLLECTOR_DEST_MAC_4 0x19
#define COLLECTOR_DEST_MAC_5 0x9a

#define SENDER_SRC_MAC_0 0x52
#define SENDER_SRC_MAC_1 0x54
#define SENDER_SRC_MAC_2 0x00
#define SENDER_SRC_MAC_3 0xd3
#define SENDER_SRC_MAC_4 0xe0
#define SENDER_SRC_MAC_5 0x0d

/* Send to the bridge interface */
// #define SEND_INTF "enp8s0"
// #define COLLECTOR_DEST_MAC_0 0x52
// #define COLLECTOR_DEST_MAC_1 0x54
// #define COLLECTOR_DEST_MAC_2 0x00
// #define COLLECTOR_DEST_MAC_3 0x80
// #define COLLECTOR_DEST_MAC_4 0x26
// #define COLLECTOR_DEST_MAC_5 0xbc

