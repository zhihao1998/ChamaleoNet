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
 * gettcp:  return a pointer to a tcp header.
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
        fprintf(fp_stdout, "gettcp: Skipping IPv4 non-initial fragment\n");
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
#ifdef SUPPORT_IPV6
  struct ipv6 *pipv6;

  if (PIP_ISV6 (pip))
    {
      pipv6 = (struct ipv6 *) pip;	/* how about all headers */
    //  return ntohs (pipv6->ip6_lngth);
      return ntohs (pipv6->ip6_lngth) + 40 - gethdrlength(pip,plast);
    }
  else /* IPv4 */
#endif
  return ntohs (pip->ip_len) - (pip->ip_hl * 4);
}
