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

typedef struct quadrant
{
  segment *seglist_head;
  segment *seglist_tail;
  Bool full;
  u_long no_of_segments;
  struct quadrant *prev;
  struct quadrant *next;
} quadrant;

typedef struct seqspace
{
  quadrant *pquad[4];
} seqspace;

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
  timeval first_time;

  /* payload information */
  u_char *ppayload; /* start of the tcp payload */
  int payload_len;
} tcp_packet;


typedef struct ptp_snap
{
  tcp_addrblock addr_pair; /* just a copy */
  struct ptp_snap *next;
  tcp_packet *ptp;
  tcp_packet **ttp_ptr;
} ptp_snap;

/* Struct mirroring the constants defined in param.h */

struct global_parameters
{
  int Max_TCP_Packets;
  int Max_UDP_Pairs;

  int List_Search_Dept;

  int Hash_Table_Size;
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