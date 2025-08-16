/*************************************************************************
 ************* C O N S T A N T S    A N D   T Y P E S  *******************
**************************************************************************/

/*Type Defination*/
const bit<16> ETHERTYPE_IPV4 = 0x0800;
const bit<16> ETHERTYPE_HONEYPOT = 0x0801;

const bit<8> IP_PROTO_ICMP = 1;
const bit<8> IP_PROTO_TCP = 6;
const bit<8> IP_PROTO_UDP = 17;

const bit<8> ICMP_TYPE_ECHO_REPLY = 0;
const bit<8> ICMP_TYPE_DEST_UNREACHABLE = 3;
const bit<8> ICMP_TYPE_ECHO_REQUEST = 8;
const bit<8> ICMP_TYPE_TIME_EXCEEDED = 11;

/* Length Defination */
const bit<8> ETH_HEADER_LEN = 14;
const bit<8> IPV4_MIN_HEAD_LEN = 20;
const bit<8> UDP_HEADER_LEN = 8;

/* Port Number */
const PortId_t CPU_PORT_1 = 64; 
const PortId_t CPU_PORT_2 = 66; 

const PortId_t PROXY_PORT = 140;

/*Table Sizing=*/
const int DEFAULT_TABLE_SIZE = 20000;

const bit<48> NF_MAC_ADDR = 0x52540050F66F;

/* Entry Idle Timeout */
/* check readme for more information */
const int ENTRY_IDLE_TIMEOUT_NBIT_POLL = 1; 

/* Internal Net Range */
const bit<32> INTERNAL_NET = 0x82C00000;
const bit<32> INTERNAL_NET_MASK = 0xFFFF0000;

const bit<3> MIRROR_TYPE_I2E = 1;
const bit<3> MIRROR_TYPE_E2E = 2;

const bit<8> PKT_TYPE_MIRROR = 1;
const bit<8> PKT_TYPE_NORMAL = 2;