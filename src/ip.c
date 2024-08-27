#include "tsdn.h"

/* given an IPv4 IP address, return a pointer to a (static) ipaddr struct */
struct ipaddr *
IPV4ADDR2ADDR(struct in_addr *addr4)
{
  static struct ipaddr addr;

  addr.addr_vers = 4;
  addr.un.ip4.s_addr = addr4->s_addr;

  return (&addr);
}

/* given an IPv6 IP address, return a pointer to a (static) ipaddr struct */
struct ipaddr *
IPV6ADDR2ADDR(struct in6_addr *addr6)
{
#ifdef SUPPORT_IPV6
  static struct ipaddr addr;

  addr.addr_vers = 6;
  memcpy(&addr.un.ip6.s6_addr, &addr6->s6_addr, 16);

  return (&addr);
#else
  return (NULL);
#endif
}

/*
 * ipcopyaddr: copy an IPv4 or IPv6 address
 */
inline void
IP_COPYADDR(ipaddr *toaddr, ipaddr fromaddr)
{
#ifdef SUPPORT_IPV6
  if (ADDR_ISV6(&fromaddr))
  {
    memcpy(toaddr->un.ip6.s6_addr, fromaddr.un.ip6.s6_addr, 16);
    toaddr->addr_vers = 6;
  }
  else
#endif
  {
    toaddr->un.ip4.s_addr = fromaddr.un.ip4.s_addr;
    toaddr->addr_vers = 4;
  }
}

/*
 * ipsameaddr: test for equality of two IPv4 or IPv6 addresses
 */
int IP_SAMEADDR(ipaddr addr1, ipaddr addr2)
{
  int ret = 0;
#ifdef SUPPORT_IPV6
  if (ADDR_ISV6(&addr1) && ADDR_ISV6(&addr2))
    ret = (memcmp(addr1.un.ip6.s6_addr, addr2.un.ip6.s6_addr, 16) == 0);
  else
#endif
      if (ADDR_ISV4(&addr2))
    ret = (addr1.un.ip4.s_addr == addr2.un.ip4.s_addr);
  return ret;
}

/*
 * findheader:  return a pointer to a L4(TCP/UDP) or ICMP header.
 * Skips either ip or ipv6 headers
 */
static void *
findheader(u_int ipproto, struct ip *pip, void **pplast)
{
  void *theheader;
  unsigned int proto_type;
  /* IPv4 is easy */
  if (PIP_ISV4(pip))
  {
    /* make sure it's what we want */
    if (pip->ip_p != ipproto)
    {
      return NULL;
    }

    /* check the fragment field, if it's not the first fragment,
       it's useless (offset part of field must be 0 */
    if ((ntohs(pip->ip_off) & 0x1fff) != 0)
    {
      if (debug > 1)
      {
        fprintf(fp_stdout, "findheader: Skipping IPv4 non-initial fragment\n");
      }
      return NULL;
    }

    /* OK, it starts here */
    theheader = ((char *)pip + 4 * pip->ip_hl);

    /* adjust plast in accordance with ip_len (really short packets get garbage) */
    if (((unsigned long)pip + ntohs(pip->ip_len) - 1) <
        (unsigned long)(*pplast))
    {
      *pplast = (void *)((unsigned long)pip + ntohs(pip->ip_len));
    }

    return (theheader);
  }
}

/*
 * gettcp:  return a pointer to a tcp header.
 * Skips either ip or ipv6 headers
 */
struct tcphdr *
gettcp(struct ip *pip, void **pplast)
{
  struct tcphdr *ptcp;
  ptcp = (struct tcphdr *)findheader(IPPROTO_TCP, pip, pplast);
  return (ptcp);
}

/*
 * getudp:  return a pointer to a udp header.
 * Skips either ip or ipv6 headers
 */
struct udphdr *
getudp(struct ip *pip, void **pplast)
{
  struct udphdr *pudp;
  pudp = (struct udphdr *)findheader(IPPROTO_UDP, pip, pplast);
  return (pudp);
}

/*
* geticmp:  return a pointer to an icmp header.
* Skips either ip or ipv6 headers
*/
struct icmphdr *
geticmp(struct ip *pip, void **pplast)
{
  struct icmphdr *picmp;
  picmp = (struct icmphdr *)findheader(IPPROTO_ICMP, pip, pplast);
  return (picmp);
}

/*
 * get_ppayload:  return a pointer to a payload.
 * Skips either ip and TCP headers
 */
char *
get_ppayload(struct tcphdr *ptcp, void **pplast)
{
  char *ppayload;
  void *payload_start = ((char *)ptcp + 4 * ptcp->th_off);
  ppayload = (char *)payload_start;
  return (ppayload);
}

/*
 * getpayloadlength: returns the length of the packet without the header.
 */
int
getpayloadlength (struct ip *pip, void *plast)
{
  return ntohs (pip->ip_len) - (pip->ip_hl * 4);
}

/* copy the IP addresses and port numbers into an addrblock structure	*/
/* in addition to copying the address, we also create a HASH value	*/
/* which is based on BOTH IP addresses and port numbers.  It allows	*/
/* faster comparisons most of the time					*/
void CopyAddr(flow_addrblock *p_flow_addr, struct ip *pip, void *p_l4_hdr)
{
    p_flow_addr->protocol = pip->ip_p;
    switch (pip->ip_p)
    {
    /* For ICMP, only use <sIP, dIP, Proto> pair for identifying a flow.  */
    case IPPROTO_ICMP:
    {
        // p_flow_addr->a_port = ((icmphdr *)p_l4_hdr)->type;
        // p_flow_addr->b_port = ((icmphdr *)p_l4_hdr)->code;
        p_flow_addr->a_port = 0;
        p_flow_addr->b_port = 0;
        break;
    }
    case IPPROTO_TCP:
    {
        p_flow_addr->a_port = ((tcphdr *)p_l4_hdr)->th_sport;
        p_flow_addr->b_port = ((tcphdr *)p_l4_hdr)->th_dport;
        break;
    }
    case IPPROTO_UDP:
    {
        p_flow_addr->a_port = ((udphdr *)p_l4_hdr)->uh_sport;
        p_flow_addr->b_port = ((udphdr *)p_l4_hdr)->uh_dport;
        break;
    }

    default:
        fprintf(fp_stderr, "CopyAddr: Unsupported Layer 4 protocol!");
        break;
    }

    IP_COPYADDR(&p_flow_addr->a_address, *IPV4ADDR2ADDR(&pip->ip_src));
    IP_COPYADDR(&p_flow_addr->b_address, *IPV4ADDR2ADDR(&pip->ip_dst));
    /* fill in the hashed address */
    p_flow_addr->hash = p_flow_addr->a_address.un.ip4.s_addr +
                        p_flow_addr->b_address.un.ip4.s_addr +
                        p_flow_addr->a_port +
                        p_flow_addr->b_port +
                        p_flow_addr->protocol;
}

int WhichDir(flow_addrblock *ppkta1, flow_addrblock *ppkta2)
{
    /* same as first packet */
    if (IP_SAMEADDR(ppkta1->a_address, ppkta2->a_address))
        if (IP_SAMEADDR(ppkta1->b_address, ppkta2->b_address))
            if ((ppkta1->a_port == ppkta2->a_port))
                if ((ppkta1->b_port == ppkta2->b_port))
                    return (C2S);

    /* reverse of first packet */
    if (IP_SAMEADDR(ppkta1->a_address, ppkta2->b_address))
        if (IP_SAMEADDR(ppkta1->b_address, ppkta2->a_address))
            if ((ppkta1->a_port == ppkta2->b_port))
                if ((ppkta1->b_port == ppkta2->a_port))
                    return (S2C);
    /* different connection */
    return (0);
}

int SameConn(flow_addrblock *ppkta1, flow_addrblock *ppkta2, int *pdir)
{
    /* Here we should also take into account the direction, since we are processing the packet rather than flow*/
    /* if the hash values are different, they can't be the same */
    if (ppkta1->hash != ppkta2->hash)
        return (0);

    /* OK, they hash the same, are they REALLY the same function */
    *pdir = WhichDir(ppkta1, ppkta2);
    return (*pdir != 0);
}