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
#include <linux/if_packet.h>
#include <Python.h>
#include <stdarg.h>
#include <stdbool.h>
#include <time.h>

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

extern int debug;

#define fp_stdout stdout
#define fp_stderr stderr

#ifndef IP_MAXPACKET
#define IP_MAXPACKET 65535
#endif /* IP_MAXPACKET */

#define PCAP_DLT_EN10MB 1 /* Ethernet (10Mb) */

struct pcap_pkthdr pcap_current_hdr;
unsigned char *pcap_current_buf;

#define PHYS_ETHER 1

void InitGlobalArrays(void);

/* Packet handle realated */
int pkt_handle(struct ether_header *peth, struct ip *pip, void *ptcp, void *plast, struct timeval *pckt_time);
struct tcphdr *gettcp(struct ip *pip, void **pplast);
struct udphdr *getudp(struct ip *pip, void **pplast);
struct icmphdr *geticmp(struct ip *pip, void **pplast);
char *get_ppayload(struct tcphdr *ptcp, void **pplast);
void trace_init(void);



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

struct pkt_list_elem
{
  struct pkt_list_elem *next;
  struct pkt_list_elem *prev;
  ip_packet *ppkt;
};

struct pkt_desc_list_elem
{
  struct pkt_desc_list_elem *next;
  struct pkt_desc_list_elem *prev;
  pkt_desc_t *pkt_desc_ptr;
};

ip_packet *pkt_alloc(void);
void pkt_release(ip_packet *relesased_ip_packet);


/* Pkt descriptor */
pkt_desc_t *pkt_desc_alloc();
void pkt_desc_release(pkt_desc_t *rel_pkt_desc);

/* Flow hash table */
flow_hash_t *flow_hash_alloc();
void flow_hash_release(flow_hash_t *flow_hash_ptr);


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
Bool internal_ip(struct in_addr adx);

/* Packet Sending */
int SendPkt(char *sendbuf, int tx_len);
int sockfd;
struct ifreq if_idx;
struct sockaddr_ll socket_address;
char ifName[IFNAMSIZ];

/* Thread Operation Function */
void *timeout_mgmt(void *args);
void *lazy_free_flow_hash(void *args);

/* Global structure for circular buffer and locks */
pthread_mutex_t circ_buf_mutex_list[TIMEOUT_LEVEL_NUM];
pthread_cond_t circ_buf_cond_list[TIMEOUT_LEVEL_NUM];
pkt_desc_t **pkt_desc_buf_list[TIMEOUT_LEVEL_NUM];
circular_buf_t *circ_buf_list[TIMEOUT_LEVEL_NUM];

pthread_mutex_t circ_buf_head_mutex_list[TIMEOUT_LEVEL_NUM];

/* connection records are stored in a hash table.  */
flow_hash_t **flow_hash_table;
pthread_mutex_t flow_hash_mutex;

flow_hash_t **lazy_flow_hash_buf;
circular_buf_t *lazy_flow_hash_circ_buf;
pthread_mutex_t lazy_flow_hash_mutex;
pthread_cond_t lazy_flow_hash_cond;

/*
 * File Operations
 */
char *readline(FILE *fp, int skip_comment, int skip_void_lines);
#define BUF_SIZE 80

/*
 * Output
 */
#define ANSI_BOLD "\x1b[1m"
#define ANSI_RESET "\x1b[0m"

void CopyAddr(flow_addrblock *p_flow_addr, struct ip *pip, void *p_l4_hdr);
int WhichDir(flow_addrblock *ppkta1, flow_addrblock *ppkta2);
int SameConn(flow_addrblock *ppkta1, flow_addrblock *ppkta2, int *pdir);
void FreePkt(ip_packet *ppkt_temp);
void FreePktDesc(pkt_desc_t *pkt_desc_ptr);
void FreeFlowHash(flow_hash_t *flow_hash_ptr);
int LazyFreeFlowHash(flow_hash_t *flow_hash_ptr);

/* Tofino Interaction */

int bfrt_tcp_flow_add_with_drop(in_addr src_ip, in_addr dst_ip, u_short src_port, u_short dst_port);
int bfrt_udp_flow_add_with_drop(in_addr src_ip, in_addr dst_ip, u_short src_port, u_short dst_port);
int bfrt_icmp_flow_add_with_drop(in_addr src_ip, in_addr dst_ip);
void bfrt_grpc_destroy();
void bfrt_grpc_init();
void *install_drop_entry(void *args);
int try_install_drop_entry(in_addr src_ip, in_addr dst_ip, ushort src_port, u_short dst_port, ushort protocol);

/* Logging */
#define DO_STATS

FILE *fp_log;
FILE *fp_stats;

typedef struct {
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

enum { LOG_TRACE, LOG_DEBUG, LOG_INFO, LOG_WARN, LOG_ERROR, LOG_FATAL };

#define log_trace(...) log_log(LOG_TRACE, __FILE__, __LINE__, __VA_ARGS__)
#define log_debug(...) log_log(LOG_DEBUG, __FILE__, __LINE__, __VA_ARGS__)
#define log_info(...)  log_log(LOG_INFO,  __FILE__, __LINE__, __VA_ARGS__)
#define log_warn(...)  log_log(LOG_WARN,  __FILE__, __LINE__, __VA_ARGS__)
#define log_error(...) log_log(LOG_ERROR, __FILE__, __LINE__, __VA_ARGS__)
#define log_fatal(...) log_log(LOG_FATAL, __FILE__, __LINE__, __VA_ARGS__)

const char* log_level_string(int level);
void log_set_lock(log_LockFn fn, void *udata);
void log_set_level(int level);
void log_set_quiet(bool enable);
int log_add_callback(log_LogFn fn, void *udata, int level);
int log_add_fp(FILE *fp, int level);

void log_log(int level, const char *file, int line, const char *fmt, ...);


/* Statistic Variables */

// Packet Counters
u_long pkt_count;

u_long tcp_pkt_count_tot;
// u_long in_tcp_pkt_count;
// u_long out_tcp_pkt_count;
// u_long local_tcp_pkt_count;

u_long udp_pkt_count_tot;
// u_long in_udp_pkt_count;
// u_long out_udp_pkt_count;
// u_long local_udp_pkt_count;

u_long icmp_pkt_count_tot;
// u_long in_icmp_pkt_count;
// u_long out_icmp_pkt_count;
// u_long local_icmp_pkt_count;

// Data Structure Counters
u_long pkt_buf_count;
u_long flow_hash_count;
u_long pkt_desc_count;
u_long circ_buf_L1_count;
u_long circ_buf_L2_count;
u_long circ_buf_L3_count;
u_long lazy_flow_hash_count;
u_long lazy_flow_hash_hit;

// Freelist Counters
u_long pkt_list_count_tot;
u_long pkt_list_count_use;
u_long flow_hash_list_count_tot;
u_long flow_hash_list_count_use;
u_long pkt_desc_list_count_tot;
u_long pkt_desc_list_count_use;

// Functionality Counters
u_long installed_entry_count_tot;
u_long installed_entry_count_tcp;
u_long installed_entry_count_udp;
u_long installed_entry_count_icmp;

u_long replied_flow_count_tot;
u_long replied_flow_count_tcp;
u_long replied_flow_count_udp;
u_long replied_flow_count_icmp;

u_long expired_pkt_count_tot;
u_long expired_pkt_count_tcp;
u_long expired_pkt_count_udp;
u_long expired_pkt_count_icmp;


