/* Define how often garbage collection scans the whole flow table */
/* Historically, this is set to half TCP_SINGLETON_TIME */
#define GARBAGE_PERIOD (TCP_SINGLETON_TIME/2)

/* Define granularity of garbage collection splitting. 
 The flow table is not scanned in one time,
 but the workload is done in GARBAGE_SPLIT_RATIO times
 IMPORTANT: it must be a divisor of GARBAGE_PERIOD,
 MAX_TCP_PACKETS and MAX_UDP_PAIRS  */
#define GARBAGE_SPLIT_RATIO 10000

/* Define the interval for garbage collection routine to be fired */
// #define GARBAGE_FIRE_TIME (GARBAGE_PERIOD/GARBAGE_SPLIT_RATIO)  

/* maximum number of concurrent TCP connection stored in the vector TTP 
Increase this number on high speed network will help ...*/
// #define MAX_TCP_PACKETS 30
#define MAX_TCP_PACKETS 360000
/* Each time the garbage collection is fired, it scans MAX_TCP_PACKETS_BURST tcp flows */
// #define MAX_TCP_PACKETS_BURST (MAX_TCP_PACKETS / GARBAGE_SPLIT_RATIO)

/* maximum number of concurrent UDP connection stored in the vector UTP 
Increase this number on high speed network will help ...*/
#define MAX_UDP_PAIRS 360000
/* Each time the garbage collection is fired, it scans MAX_UDP_PAIRS_BURST upd flows */
// #define MAX_UDP_PAIRS_BURST (MAX_UDP_PAIRS / GARBAGE_SPLIT_RATIO)

/* max depth of the linear serch in the previous vector... */
#define LIST_SEARCH_DEPT 200

/* connection records are stored in a hash table.  Buckets are linked	*/
/* lists sorted by most recent access.					*/
/* oughta be prime  and larger than MAX_TCP_PACKETS */
#define HASH_TABLE_SIZE 2000000

/* TIMEOUT in microseconds: timeout to consider a packet is expired (no answering from server) */
#define TIMEOUT_LEVEL_NUM 3
#define TIMEOUT_LEVEL_1 100000
#define TIMEOUT_LEVEL_2 50000  
#define TIMEOUT_LEVEL_3 20000   

#define LAZY_FREEING_TIMEOUT 100000000


/* Max number of nets to check if ip is internal or external */
#define MAX_INTERNAL_HOSTS  100
