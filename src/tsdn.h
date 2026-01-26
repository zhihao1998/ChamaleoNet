#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <net/ethernet.h>
#include <string.h>
#include <assert.h>
#include <pthread.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <linux/if_packet.h>
#include <Python.h>
#include <stdarg.h>
#include <stdbool.h>
#include <time.h>
#include <signal.h>
#include <dirent.h>
#include <getopt.h>
#include <stdatomic.h>
#include <inttypes.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "struct.h"
#include "param.h"

/* tcpdump header (ether.h) defines ETHER_HDRLEN) */
#ifndef ETHER_HDRLEN
#define ETHER_HDRLEN 14
#endif

/*
 * Macros to simplify access to IPv4/IPv6 header fields
 */
#define PIP_VERS(pip) (((struct ip *)(pip))->ip_v)
#define PIP_ISV4(pip) (PIP_VERS(pip) == 4)
#define PIP_V4(pip) ((struct ip *)(pip))
#define PIP_EITHERFIELD(pip, fld4, fld6) \
  (PIP_ISV4(pip) ? (PIP_V4(pip)->fld4) : (PIP_V6(pip)->fld6))
#define PIP_LEN(pip) (PIP_EITHERFIELD(pip, ip_len, ip6_lngth))

/*
 * Macros to simplify access to IPv4/IPv6 addresses
 */
#define ADDR_VERSION(paddr) ((paddr)->addr_vers)
#define ADDR_ISV4(paddr) (ADDR_VERSION((paddr)) == 4)

struct ipaddr *IPV4ADDR2ADDR(struct in_addr *addr4);

void IP_COPYADDR(ipaddr *toaddr, ipaddr fromaddr);
int IP_SAMEADDR(ipaddr addr1, ipaddr addr2);

/* TCP flags macros */
#define SYN_SET(ptcp) ((ptcp)->th_flags & TH_SYN)
#define FIN_SET(ptcp) ((ptcp)->th_flags & TH_FIN)
#define ACK_SET(ptcp) ((ptcp)->th_flags & TH_ACK)
#define RESET_SET(ptcp) ((ptcp)->th_flags & TH_RST)
#define PUSH_SET(ptcp) ((ptcp)->th_flags & TH_PUSH)
#define URGENT_SET(ptcp) ((ptcp)->th_flags & TH_URG)
#define FLAG6_SET(ptcp) ((ptcp)->th_flags & 0x40)
#define FLAG7_SET(ptcp) ((ptcp)->th_flags & 0x80)
#define CWR_SET(ptcp) ((ptcp)->th_x2 & TH_CWR)
#define ECN_ECHO_SET(ptcp) ((ptcp)->th_x2 & TH_ECN_ECHO)

void *MallocZ(int);
void *ReallocZ(void *oldptr, int obytes, int nbytes);
void *MMmalloc(size_t size, const char *f_name);

/* connection naming information */
Bool internal_src;
Bool internal_dst;

#define C2S 1
#define S2C -1

#define fp_stdout stdout
#define fp_stderr stderr

#define PCAP_DLT_EN10MB 1 /* Ethernet (10Mb) */

#define PHYS_ETHER 1

void InitGlobalArrays(void);

/* Packet handle realated */
int pkt_handle(struct ether_header *peth, struct ip *pip, void *ptcp, void *plast);
struct tcphdr *gettcp(struct ip *pip, void **pplast);
struct udphdr *getudp(struct ip *pip, void **pplast);
struct icmphdr *geticmp(struct ip *pip, void **pplast);
char *get_ppayload(struct tcphdr *ptcp, void **pplast);
void trace_init(void);
void trace_check(void);
void trace_cleanup(void);

int getpayloadlength(struct ip *pip, void *plast);

/*
 * timeval compare macros
 */
#define tv_ge(lhs, rhs) (tv_cmp((lhs), (rhs)) >= 0)
#define tv_gt(lhs, rhs) (tv_cmp((lhs), (rhs)) > 0)
#define tv_le(lhs, rhs) (tv_cmp((lhs), (rhs)) <= 0)
#define tv_lt(lhs, rhs) (tv_cmp((lhs), (rhs)) < 0)
#define tv_eq(lhs, rhs) (tv_cmp((lhs), (rhs)) == 0)

double elapsed(timeval, timeval);
int tv_cmp(struct timeval lhs, struct timeval rhs);
void tv_sub(struct timeval *plhs, struct timeval rhs);
int tv_sub_2(struct timeval lhs, struct timeval rhs);
void tv_add(struct timeval *plhs, struct timeval rhs);
Bool tv_same(struct timeval lhs, struct timeval rhs);

/* handy constants */
#define US_PER_SEC 1000000 /* microseconds per second */
#define MS_PER_SEC 1000    /* milliseconds per second */
#define US_PER_MS 1000     /* microseconds per millisecond */

/* memory management and garbage collection routines (freelist) */
ip_packet *pkt_alloc(void);
void pkt_release(ip_packet *relesased_ip_packet);

/* Packet Descriptor */
typedef struct pkt_desc_t pkt_desc_t;
pkt_desc_t *pkt_desc_alloc();
void pkt_desc_release(pkt_desc_t *released_pkt_desc);

/* Flow hash table */
flow_hash_t *flow_hash_alloc();
void flow_hash_release(flow_hash_t *flow_hash_ptr);

/* Table Entry Buffer */
table_entry_t *table_entry_alloc();
void table_entry_release(table_entry_t *rel_table_entry_ptr);

/* Circular Buffer Related */
// Opaque circular buffer structure
typedef struct circular_buf_t circular_buf_t;
/// Pass in a storage buffer and size
/// Returns a circular buffer handle
circular_buf_t *circular_buf_init(void **buf_space, size_t size);
/// Free a circular buffer structure.
/// Does not free data buffer; owner is responsible for that
void circular_buf_free(circular_buf_t *me);
/// Reset the circular buffer to empty, head == tail
void circular_buf_reset(circular_buf_t *me);
/// Put version 1 continues to add data
void **circular_buf_try_put(circular_buf_t *me, void *buf_slot_ptr);
/// Retrieve a value from the buffer
/// Returns 0 on success, -1 if the buffer is empty
int circular_buf_get(circular_buf_t *me, void **buf_slot_ptr_ptr);
/// Returns true if the buffer is empty
Bool circular_buf_empty(circular_buf_t *me);
/// Returns true if the buffer is full
Bool circular_buf_full(circular_buf_t *me);
/// Returns the maximum capacity of the buffer
size_t circular_buf_capacity(circular_buf_t *me);
/// Returns the current number of elements in the buffer
size_t circular_buf_size(circular_buf_t *me);
int circular_buf_peek_head(circular_buf_t *me, void **buf_slot_ptr_ptr);

/* Internal Network / Host */
int LoadInternalNets(char *file);
int LoadResponderNets(char *file);
Bool internal_ip(struct in_addr adx);
Bool responder_ip(struct in_addr adx);

/* Packet Sending */
int SendPkt(char *sendbuf, int tx_len);
int sockfd;
struct ifreq if_idx;
struct sockaddr_ll socket_address;
char ifName[IFNAMSIZ];

/* connection records are stored in a hash table.  */
flow_hash_t **flow_hash_table;

/*
 * File Operations
 */
char *readline(FILE *fp, int skip_comment, int skip_void_lines);
#define BUF_SIZE 80

void CopyAddr(flow_addrblock *p_flow_addr, struct ip *pip, void *p_l4_hdr);
int WhichDir(flow_addrblock *ppkta1, flow_addrblock *ppkta2);
int SameConn(flow_addrblock *ppkta1, flow_addrblock *ppkta2, int *pdir);
void FreePkt(ip_packet *ppkt_temp);
void FreeFlowHash(flow_hash_t *flow_hash_ptr);

void check_timeout_periodic();
void check_timeout_lazy();

/* Tofino Interaction */

int bfrt_active_host_tbl_add_with_drop(in_addr internal_ip, u_short internal_port, u_short ip_protocol);
void bfrt_grpc_init();
void *install_thead_main(void *args);
int try_install_p4_entry(in_addr service_ip, ushort service_port, ushort service_protocol);
int bfrt_get_table_usage();
int bfrt_get_local_entry_number();
int clean_all_idle_entries();
uint64_t entry_circ_buf_size();
int bfrt_add_batch_entries(PyObject *py_arg_tuple);

/* Logging */
FILE *fp_log;
FILE *fp_stats;

typedef struct
{
  va_list ap;
  const char *fmt;
  const char *file;
  struct timeval *time;
  void *udata;
  int line;
  int level;
} log_Event;

typedef void (*log_LogFn)(log_Event *ev);
typedef void (*log_LockFn)(bool lock, void *udata);

enum
{
  LOG_STATS,
  LOG_DEBUG,
  LOG_INFO,
  LOG_WARN,
  LOG_ERROR,
  LOG_FATAL
};

#define log_stats(...) log_log(LOG_STATS, __FILE__, __LINE__, __VA_ARGS__)
#define log_debug(...) log_log(LOG_DEBUG, __FILE__, __LINE__, __VA_ARGS__)
#define log_info(...) log_log(LOG_INFO, __FILE__, __LINE__, __VA_ARGS__)
#define log_warn(...) log_log(LOG_WARN, __FILE__, __LINE__, __VA_ARGS__)
#define log_error(...) log_log(LOG_ERROR, __FILE__, __LINE__, __VA_ARGS__)
#define log_fatal(...) log_log(LOG_FATAL, __FILE__, __LINE__, __VA_ARGS__)

const char *log_level_string(int level);
void log_set_lock(log_LockFn fn, void *udata);
void log_set_level(int level);
void log_set_quiet(bool enable);
int log_add_callback(log_LogFn fn, void *udata, int level);
int log_add_fp(FILE *fp, int level);

void log_log(int level, const char *file, int line, const char *fmt, ...);

/* Statistic Variables */

// Packet Counters
uint64_t pkt_count;

uint64_t tcp_pkt_count_tot;
// uint64_t in_tcp_pkt_count;
// uint64_t out_tcp_pkt_count;
// uint64_t local_tcp_pkt_count;

uint64_t udp_pkt_count_tot;
// uint64_t in_udp_pkt_count;
// uint64_t out_udp_pkt_count;
// uint64_t local_udp_pkt_count;

uint64_t icmp_pkt_count_tot;
// uint64_t in_icmp_pkt_count;
// uint64_t out_icmp_pkt_count;
// uint64_t local_icmp_pkt_count;

/* Error Packets */
uint64_t send_pkt_error_count;

// Data Structure Counters
uint64_t pkt_buf_count;
uint64_t flow_hash_count;
uint64_t lazy_flow_hash_count;

// Freelist Counters
uint64_t pkt_list_count_tot;
uint64_t pkt_list_count_use;
uint64_t pkt_desc_list_count_tot;
uint64_t pkt_desc_list_count_use;
uint64_t flow_hash_list_count_tot;
uint64_t flow_hash_list_count_use;

// Functionality Counters
uint64_t installed_entry_count_tot;
// uint64_t installed_entry_count_tcp;
// uint64_t installed_entry_count_udp;
// uint64_t installed_entry_count_icmp;

uint64_t install_buf_size;

uint64_t entry_install_error_count;
uint64_t entry_install_dedup_count;

uint64_t replied_flow_count_tot;
// uint64_t replied_flow_count_tcp;
// uint64_t replied_flow_count_udp;
// uint64_t replied_flow_count_icmp;
uint64_t install_rule_batch_count;

uint64_t expired_pkt_count_tot;
uint64_t expired_pkt_count_tcp;
uint64_t expired_pkt_count_udp;
uint64_t expired_pkt_count_icmp;

// Flow Entry Counters
uint64_t active_host_tbl_entry_count;
uint64_t local_entry_count;

extern timeval current_time;
extern timeval last_log_time;
extern timeval last_pkt_cleaned_time;
extern timeval last_hash_cleaned_time;
extern timeval last_idle_cleaned_time;

/* Experiments to justify the hash table usage */
#ifdef FLOW_HASH_MEASURE
uint64_t flow_hash_total_lookups;
uint64_t flow_hash_collision_lookups;
uint64_t flow_hash_total_probes;
uint64_t flow_hash_missed_lookups;
uint64_t flow_hash_max_depth;
double flow_hash_avg_probes;
uint64_t flow_hash_p99_depth;
#define FLOW_HASH_MAX_DEPTH 10
uint64_t flow_hash_depth_hist[FLOW_HASH_MAX_DEPTH + 1];
#endif

/* Whether to activate the host liveness monitoring */
#ifdef HOST_LIVENESS_MONITOR

#define INTERNAL_HOST_NUM 65536
#define ACTIVE_HOST_UPDATE_PERIOD 1000000 // 1s

extern timeval last_active_entry_update_time;
extern timeval last_active_host_merge_time;
extern uint8_t active_internal_host_entry[INTERNAL_HOST_NUM];
extern uint8_t active_internal_host_send[INTERNAL_HOST_NUM];
extern uint8_t active_internal_host[INTERNAL_HOST_NUM];
pthread_mutex_t active_internal_host_entry_mutex;
uint32_t base_ip_int;
// bfrt side
void bfrt_update_active_host_list();
uint32_t count_active_hosts();
void merge_host_liveness(void);
uint8_t check_internal_host_liveness(uint32_t ip_src);

int append_host_alive_after_l4(struct ether_header *peth, struct ip *pip, int tlen, uint8_t host_alive);
int append_host_alive_to_tos(struct ether_header *peth, struct ip *pip, int tlen, uint8_t host_alive);
#endif

uint32_t ip_to_int(const char *ip_str);


/* Install entry using Unix Direct Socket */
#define ENTRY_INSTALL_SOCKET
#ifdef ENTRY_INSTALL_SOCKET
#define P4_OP_INSTALL 1

int p4_batch_init(const char *uds_path);
int p4_batch_add_rule(struct in_addr ip, uint16_t port_host, uint8_t proto);
int p4_batch_flush(void);


static inline uint64_t now_ms_monotonic(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ull + (uint64_t)ts.tv_nsec / 1000000ull;
}

static inline uint64_t flow_key_u64(uint32_t ip_be, uint16_t port, uint8_t proto) {
    // ip_be: network order; treat as 32-bit blob
    return ((uint64_t)ip_be << 32) | ((uint64_t)port << 8) | (uint64_t)proto;
}

// 一个简单的 2^N 桶表，碰撞就覆盖（近似去重，足够用了）
#define DEDUP_BITS 20
#define DEDUP_SIZE (1u << DEDUP_BITS)

static uint64_t dedup_keys[DEDUP_SIZE];
static uint64_t dedup_last_ms[DEDUP_SIZE];

static inline int dedup_should_send(uint32_t ip_be, uint16_t port, uint8_t proto, uint64_t cooldown_ms) {
    uint64_t k = flow_key_u64(ip_be, port, proto);
    uint32_t idx = (uint32_t)((k * 11400714819323198485ull) >> (64 - DEDUP_BITS)); // multiplicative hash
    uint64_t now = now_ms_monotonic();

    if (dedup_keys[idx] == k) {
        if (now - dedup_last_ms[idx] < cooldown_ms) return 0; // 不发送
        dedup_last_ms[idx] = now;
        return 1;
    }
    // 新 key 或碰撞覆盖
    dedup_keys[idx] = k;
    dedup_last_ms[idx] = now;
    return 1;
}
#endif
