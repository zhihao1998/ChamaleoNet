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
#include <net/ethernet.h>
#include <string.h>
#include <assert.h>
#include <pthread.h> 
#include <unistd.h>

#include "struct.h"
#include "param.h"
#include "data_structure.h"

/* tcpdump header (ether.h) defines ETHER_HDRLEN) */
#ifndef ETHER_HDRLEN
#define ETHER_HDRLEN 14
#endif

#define C2S 1
#define S2C -1

/*
 * Macros to simplify access to IPv4/IPv6 header fields
 */
#define PIP_VERS(pip) (((struct ip *)(pip))->ip_v)
#ifdef SUPPORT_IPV6
#define PIP_ISV6(pip) (PIP_VERS(pip) == 6)
#else
#define PIP_ISV6(pip) FALSE
#endif
#define PIP_ISV4(pip) (PIP_VERS(pip) == 4)
#define PIP_V6(pip) ((struct ipv6 *)(pip))
#define PIP_V4(pip) ((struct ip *)(pip))
#define PIP_EITHERFIELD(pip, fld4, fld6) \
    (PIP_ISV4(pip) ? (PIP_V4(pip)->fld4) : (PIP_V6(pip)->fld6))
#define PIP_LEN(pip) (PIP_EITHERFIELD(pip, ip_len, ip6_lngth))

/*
 * Macros to simplify access to IPv4/IPv6 addresses
 */
#define ADDR_VERSION(paddr) ((paddr)->addr_vers)
#define ADDR_ISV4(paddr) (ADDR_VERSION((paddr)) == 4)
#ifdef SUPPORT_IPV6
#define ADDR_ISV6(paddr) (ADDR_VERSION((paddr)) == 6)
#else
#define ADDR_ISV6(paddr) (FALSE)
#endif
struct ipaddr *IPV4ADDR2ADDR(struct in_addr *addr4);
struct ipaddr *IPV6ADDR2ADDR(struct in6_addr *addr6);

void IP_COPYADDR(ipaddr *toaddr, ipaddr fromaddr);
int IP_SAMEADDR(ipaddr addr1, ipaddr addr2);

/* Global struct with the content of param.h*/
struct global_parameters GLOBALS;

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

/* connection naming information */
Bool internal_src;
Bool internal_dst;

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

void InitGlobals(void);

/* TCP realated */
int tcp_handle(struct ip *, struct tcphdr *ptcp, void *plast, int *dir, struct timeval *pckt_time);
struct tcphdr *gettcp (struct ip *pip, void **pplast);
char *get_ppayload(struct tcphdr *ptcp, void **pplast);
void trace_init (void);
void print_ttp();

/* Return Values for tcp_flow_stat() and udp_flow_stat() */
#define FLOW_STAT_NULL  0
#define FLOW_STAT_OK    1
#define FLOW_STAT_DUP   2
#define FLOW_STAT_NONE  3
#define FLOW_STAT_SHORT 4

extern Bool warn_printtrunc;

extern u_long pnum;

int getpayloadlength (struct ip *pip, void *plast);

/*
 * timeval compare macros
 */
#define tv_ge(lhs,rhs) (tv_cmp((lhs),(rhs)) >= 0)
#define tv_gt(lhs,rhs) (tv_cmp((lhs),(rhs)) >  0)
#define tv_le(lhs,rhs) (tv_cmp((lhs),(rhs)) <= 0)
#define tv_lt(lhs,rhs) (tv_cmp((lhs),(rhs)) <  0)
#define tv_eq(lhs,rhs) (tv_cmp((lhs),(rhs)) == 0)

double elapsed (timeval, timeval);
int tv_cmp (struct timeval lhs, struct timeval rhs);

extern timeval current_time;

void tv_sub (struct timeval *plhs, struct timeval rhs);
void tv_add (struct timeval *plhs, struct timeval rhs);
Bool tv_same (struct timeval lhs, struct timeval rhs);

/* handy constants */
#define US_PER_SEC 1000000	/* microseconds per second */
#define MS_PER_SEC 1000		/* milliseconds per second */
#define US_PER_MS  1000     /* microseconds per millisecond */

// host_status **active_host_hashtable;

Bool internal_ip(struct in_addr adx);

// void *timeout_mgmt(void *args);