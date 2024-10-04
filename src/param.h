
/* Define how often garbage collection scans the whole flow table */
/* Historically, this is set to half TCP_SINGLETON_TIME */
#define GARBAGE_PERIOD 10000

/* Define granularity of garbage collection splitting. 
 The flow table is not scanned in one time,
 but the workload is done in GARBAGE_SPLIT_RATIO times
 IMPORTANT: it must be a divisor of GARBAGE_PERIOD,
 PKT_BUF_SIZE and MAX_UDP_PAIRS  */
#define GARBAGE_SPLIT_RATIO 5000

/* Define the interval for garbage collection routine to be fired */
// #define GARBAGE_FIRE_TIME (GARBAGE_PERIOD/GARBAGE_SPLIT_RATIO)  

/* maximum number of concurrent TCP connection stored in the vector TTP 
Increase this number on high speed network will help ...*/

#define PKT_BUF_SIZE 10000
/* Each time the garbage collection is fired, it scans PKT_BUF_SIZE_BURST tcp flows */
// #define PKT_BUF_SIZE_BURST (PKT_BUF_SIZE / GARBAGE_SPLIT_RATIO)

/* max depth of the linear search in the previous vector... */
#define LIST_SEARCH_DEPT 200

/* connection records are stored in a hash table.  Buckets are linked	*/
/* lists sorted by most recent access.					*/
/* oughta be prime  and larger than PKT_BUF_SIZE */
#define HASH_TABLE_SIZE 20000

/* TIMEOUT in microseconds: timeout to consider a packet is expired (no answering from server) */
#define TIMEOUT_LEVEL_NUM 3
#define TIMEOUT_LEVEL_1 20000
#define TIMEOUT_LEVEL_2 50000  
#define TIMEOUT_LEVEL_3 20000   

/* Every LAZY_FREEING_PERIOD, scan LAZY_FREEING_RATIO entries. */
/* After LAZY_FREEING_PERIOD / (HASH_TABLE_SIZE / LAZY_FREEING_RATIO), the whole hash table is completely scanned once */
/* So the lazy free timeout should be 2*LAZY_FREEING_PERIOD / (HASH_TABLE_SIZE / LAZY_FREEING_RATIO) */
#define LAZY_FREEING_RATIO 2000
#define LAZY_FREEING_PERIOD 50000
#define LAZY_FREEING_TIMEOUT 1000000

/* 
* Switch GRPC Client 
*/

/* size of the circular buffer of the pending entry list to be installed */
#define ENTRY_BUF_SIZE 100000

/* polling time for checking the idle entries in P4 tables */
#define ENTRY_IDLE_TIMEOUT 5000000


/* Max number of nets to check if ip is internal or external */
#define MAX_INTERNAL_HOSTS  100


/* Interfaces to capture and send packets */
#define RECV_INTF "enp8s0"
#define SEND_INTF "brtest"

/* Logging Sampling granularity */
#define PKT_LOG_SAMPLE_CNT 1000      // pkt_count
#define TIMEOUT_SAMPLE_CNT 1000      // tot_expired_pkt_count
#define STATS_LOG_SAMPLE_TIME 10000  //us
