typedef u_long hash;

/* type for a timestamp */
typedef struct timeval timeval;
#define ZERO_TIME(ptv) (((ptv)->tv_sec == 0) && ((ptv)->tv_usec == 0))
#define time2double(t) ((double)(t).tv_sec * 1000000 + (double)(t).tv_usec)

/* type for a Boolean */
typedef u_char Bool;
#define TRUE 1
#define FALSE 0
#define BOOL2STR(b) (b) ? "TRUE" : "FALSE"

#define MAX_PKT_LENGTH 1518

/* type for an IP address */
/* IP address can be either IPv4 or IPv6 */
typedef struct ipaddr
{
  u_char addr_vers; /* 4 or 6 */
  union
  {
    struct in_addr ip4;
#ifdef SUPPORT_IPV6
    struct in6_addr ip6;
#endif
  } un;
} ipaddr;

typedef struct icmphdr icmphdr;
typedef struct tcphdr tcphdr;
typedef struct udphdr udphdr;
typedef struct in_addr in_addr;


typedef struct
{
  ipaddr a_address;
  ipaddr b_address;
  u_short a_port;
  u_short b_port;
  u_short protocol;
  hash hash;
} flow_addrblock;

typedef struct ip_packet
{
  /* endpoint identification */
  flow_addrblock addr_pair;

  /* connection naming information */
  Bool internal_src;
  Bool internal_dst;

  /* raw packet (from Ether) information */
  int pkt_len;
  u_char raw_pkt[MAX_PKT_LENGTH]; /* start of the whole raw packet */

  /* location in the pkt_arr array */
  int loc_pkt_arr;
} ip_packet;

/* incoming/outgoing based on Ethernet MAC addresses */
typedef struct eth_filter
{
  int tot_internal_eth;
  // uint8_t addr[MAX_INTERNAL_ETHERS][6];
  uint8_t **addr;
} eth_filter;

enum ip_direction {
 DEFAULT_NET     = 0,
 SRC_IN_DST_IN   = 1,
 SRC_IN_DST_OUT  = 2,
 SRC_OUT_DST_IN  = 3,
 SRC_OUT_DST_OUT = 4
};

/* Circular Buffer Related */

typedef struct flow_hash_t flow_hash_t;

typedef struct pkt_desc_t {
  ip_packet * pkt_ptr;
  timeval recv_time;
  flow_hash_t *flow_hash_ptr;
} pkt_desc_t;

typedef struct circular_buf_t {
  void ** buf_space;
	size_t head;
	size_t tail;
	size_t max; //of the buffer
}circular_buf_t;

typedef struct flow_hash_t
{
  flow_addrblock addr_pair;
  struct flow_hash_t*next;
  pkt_desc_t *pkt_desc_ptr;
  pkt_desc_t **pkt_desc_ptr_ptr;
  Bool lazy_pending;
  timeval resp_time;
} flow_hash_t;


typedef struct timeout_mgmt_args
{
  int timeout;
  circular_buf_t *circ_buf;
  pthread_mutex_t *g_tMutex_ptr;
  pthread_cond_t *cond_ptr;
  pthread_mutex_t *head_mutex_ptr;
}timeout_mgmt_args;