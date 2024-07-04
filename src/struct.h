/* type for a TCP port number */
typedef u_short portnum;

/* type for a TCP sequence number, ACK, FIN, or SYN */
typedef u_int32_t seqnum;

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

#define MAX_PAYLOAD_LENGTH 1500

typedef struct segment
{
  seqnum seq_firstbyte; /* seqnumber of first byte */
  seqnum seq_lastbyte;  /* seqnumber of last byte */
  u_char retrans;       /* retransmit count */
  u_int acked;          /* how MANY times has has it been acked? */
  timeval time;         /* time the segment was sent */
  /* LM start - add field to implement an heuristic to identify
     loss packets within a flow
   */
  u_short ip_id; /* 16 bit ip identification field  */
  char type_of_segment;
  /* LM stop */
  struct segment *next;
  struct segment *prev;
} segment;

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

typedef struct tcphdr tcphdr;

typedef struct
{
  ipaddr a_address;
  ipaddr b_address;
  portnum a_port;
  portnum b_port;
  hash hash;
} tcp_addrblock;

typedef struct tcp_packet
{
  /* endpoint identification */
  tcp_addrblock addr_pair;

  /* connection naming information */
  Bool internal_src;
  Bool internal_dst;

  /* connection information */
  timeval arrival_time;

  /* payload information */
  int payload_len;
  u_char payload[MAX_PAYLOAD_LENGTH]; /* start of the tcp payload */

  /* location in the ttp array */
  int loc_ttp;
} tcp_packet;


typedef struct ptp_snap
{
  tcp_addrblock addr_pair; /* just a copy */
  struct ptp_snap *next;
  tcp_packet *ptp;
  tcp_packet **ttp_ptr;
} ptp_snap;

typedef struct host_status
{
  ipaddr ip_addr;
  hash hval;  
  timeval last_time;
}host_status;

/* Struct mirroring the constants defined in param.h */

struct global_parameters
{
  int Max_TCP_Packets;
  int Max_UDP_Pairs;

  int List_Search_Dept;

  int Hash_Table_Size;
  int TCP_Idle_Time;
};

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

