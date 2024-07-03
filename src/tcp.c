#include "tsdn.h"

/* tcp database stats */
long not_id_p;
int search_count = 0;

extern unsigned long int fcount;
extern unsigned long int f_TCP_count;

int num_tcp_packets = 0;                   /* how many packets we've allocated */
tcp_packet **ttp = NULL;                   /* array of pointers to allocated packets */
struct tp_list_elem *tp_list_start = NULL; /* starting point of the linked list */
struct tp_list_elem *tp_list_curr = NULL;  /* current insert point of the linked list */
u_long tcp_trace_count_outgoing = 0;
u_long tcp_trace_count_incoming = 0;
u_long tcp_trace_count_local = 0;

Bool warn_MAX_ = TRUE;

/* copy the IP addresses and port numbers into an addrblock structure	*/
/* in addition to copying the address, we also create a HASH value	*/
/* which is based on BOTH IP addresses and port numbers.  It allows	*/
/* faster comparisons most of the time					*/
void CopyAddr(tcp_addrblock *ptpa,
              struct ip *pip, portnum port1, portnum port2)
{
    ptpa->a_port = port1;
    ptpa->b_port = port2;

    if (PIP_ISV4(pip))
    { /* V4 */
        IP_COPYADDR(&ptpa->a_address, *IPV4ADDR2ADDR(&pip->ip_src));
        IP_COPYADDR(&ptpa->b_address, *IPV4ADDR2ADDR(&pip->ip_dst));
        /* fill in the hashed address */
        ptpa->hash = ptpa->a_address.un.ip4.s_addr + ptpa->b_address.un.ip4.s_addr + ptpa->a_port + ptpa->b_port;
    }
#ifdef SUPPORT_IPV6
    else
    { /* V6 */
        int i;
        struct ipv6 *pip6 = (struct ipv6 *)pip;
        IP_COPYADDR(&ptpa->a_address, *IPV6ADDR2ADDR(&pip6->ip6_saddr));
        IP_COPYADDR(&ptpa->b_address, *IPV6ADDR2ADDR(&pip6->ip6_daddr));
        /* fill in the hashed address */
        ptpa->hash = ptpa->a_port + ptpa->b_port;
        for (i = 0; i < 16; ++i)
        {
            ptpa->hash += ptpa->a_address.un.ip6.s6_addr[i];
            ptpa->hash += ptpa->b_address.un.ip6.s6_addr[i];
        }
    }
#endif
}

int WhichDir(tcp_addrblock *ptpa1, tcp_addrblock *ptpa2)
{

#ifdef BROKEN_COMPILER
    /* sorry for the ugly nested 'if', but a 4-way conjunction broke my */
    /* Optimizer (under 'gcc version cygnus-2.0.2')                     */

    /* same as first packet */
    if (IP_SAMEADDR(ptpa1->a_address, ptpa2->a_address))
        if (IP_SAMEADDR(ptpa1->b_address, ptpa2->b_address))
            if ((ptpa1->a_port == ptpa2->a_port))
                if ((ptpa1->b_port == ptpa2->b_port))
                    return (C2S);

    /* reverse of first packet */
    if (IP_SAMEADDR(ptpa1->a_address, ptpa2->b_address))
        if (IP_SAMEADDR(ptpa1->b_address, ptpa2->a_address))
            if ((ptpa1->a_port == ptpa2->b_port))
                if ((ptpa1->b_port == ptpa2->a_port))
                    return (S2C);
#else  /* BROKEN_COMPILER */
    /* same as first packet */
    if (IP_SAMEADDR(ptpa1->a_address, ptpa2->a_address) &&
        IP_SAMEADDR(ptpa1->b_address, ptpa2->b_address) &&
        (ptpa1->a_port == ptpa2->a_port) && (ptpa1->b_port == ptpa2->b_port))
        return (C2S);

    /* reverse of first packet */
    if (IP_SAMEADDR(ptpa1->a_address, ptpa2->b_address) &&
        IP_SAMEADDR(ptpa1->b_address, ptpa2->a_address) &&
        (ptpa1->a_port == ptpa2->b_port) && (ptpa1->b_port == ptpa2->a_port))
        return (S2C);
#endif /* BROKEN_COMPILER */

    /* different connection */
    return (0);
}

int SameConn(tcp_addrblock *ptpa1, tcp_addrblock *ptpa2, int *pdir)
{
    /* Here we should also take into account the direction, since we are processing the packet rather than flow*/
    /* if the hash values are different, they can't be the same */
    if (ptpa1->hash != ptpa2->hash)
        return (0);

    /* OK, they hash the same, are they REALLY the same function */
    *pdir = WhichDir(ptpa1, ptpa2);
    return (*pdir != 0);
}

static tcp_packet **
NewTTP_2(struct ip *pip, struct tcphdr *ptcp, void *plast)
{
    tcp_packet *ptp;
    int old_new_tcp_packets = num_tcp_packets;
    int steps = 0;

    /* look for the next eventually available free block */
    num_tcp_packets++;
    num_tcp_packets = num_tcp_packets % GLOBALS.Max_TCP_Packets;

    /* make a new one, if possible */
    while ((num_tcp_packets != old_new_tcp_packets) && (ttp[num_tcp_packets] != NULL) && (steps < GLOBALS.List_Search_Dept))
    {
        steps++;
        /* look for the next one */
        //         fprintf (fp_stdout, "%d %d\n", num_tcp_pairs, old_new_tcp_pairs);
        num_tcp_packets++;
        num_tcp_packets = num_tcp_packets % GLOBALS.Max_TCP_Packets;
    }
    if (ttp[num_tcp_packets] != NULL)
    {
        if (warn_MAX_)
        {
            fprintf(fp_stderr, "\n"
                               "ooopsss: number of simultaneous connection opened is greater then the maximum supported number!\n"
                               "you have to rebuild the source with a larger LIST_SEARCH_DEPT defined!\n"
                               "or possibly with a larger MAX_TCP_PACKETS defined!\n");
        }
        warn_MAX_ = FALSE;
        return (NULL);
    }

    /* create a new TCP pair record and remember where you put it */
    ptp = ttp[num_tcp_packets] = tp_alloc();

    /* grab the address from this packet */
    CopyAddr(&ptp->addr_pair,
             pip, ntohs(ptcp->th_sport), ntohs(ptcp->th_dport));

    ptp->internal_src = internal_src;
    ptp->internal_dst = internal_dst;

    ptp->payload_len = getpayloadlength(pip, plast) - ptcp->th_off * 4;
    ptp->ppayload = get_payload(ptcp, &plast);

    if (debug > 1)
    {
        fprintf(fp_stdout, "storing a new TCP SYN packet from %s:%d to %s:%d with %d bytes of payload %c%c...\n",
                inet_ntoa(pip->ip_src),
                ntohs(ptcp->th_sport),
                inet_ntoa(pip->ip_dst),
                ntohs(ptcp->th_dport),
                ptp->payload_len,
                (char)ptp->ppayload[0],
                (char)ptp->ppayload[1]);
    }
    return (&ttp[num_tcp_packets]);
}

static ptp_snap *
NewPTPH_2(void)
{
    return (ptph_alloc());
}

/* connection records are stored in a hash table.  Buckets are linked	*/
/* lists sorted by most recent access.					*/

// ptp_snap *ptp_hashtable[HASH_TABLE_SIZE] = { NULL };
ptp_snap **ptp_hashtable;

static ptp_snap **
FindTTP(struct ip *pip, struct tcphdr *ptcp, void *plast, int *pdir)
{

    ptp_snap **pptph_head = NULL;
    ptp_snap *ptph;
    ptp_snap *ptph_last;
    static tcp_packet **temp_ttp;

    tcp_addrblock tp_in;
    int dir;
    hash hval;

    /* grab the address from this packet */
    CopyAddr(&tp_in, pip, ntohs(ptcp->th_sport), ntohs(ptcp->th_dport));

    /* grab the hash value (already computed by CopyAddr) */
    hval = tp_in.hash % GLOBALS.Hash_Table_Size;

    ptph_last = NULL;
    pptph_head = &ptp_hashtable[hval];

    for (ptph = *pptph_head; ptph; ptph = ptph->next)
    {
        ++search_count;

        if (SameConn(&tp_in, &ptph->addr_pair, &dir))
        {
            /* OK, this looks good, suck it into memory */
            tcp_packet *ptp = ptph->ptp;

            /* move to head of access list (unless already there) */
            if (ptph != *pptph_head)
            {
                ptph_last->next = ptph->next; /* unlink */
                ptph->next = *pptph_head;     /* move to head */
                *pptph_head = ptph;
            }
            *pdir = dir;

            if (debug > 1)
            {
                fprintf(fp_stdout, "found a existing TCP SYN packet from %s:%d to %s:%d with %d bytes of payload %c%c...\n",
                        inet_ntoa(ptp->addr_pair.a_address.un.ip4),
                        ptp->addr_pair.a_port,
                        inet_ntoa(ptp->addr_pair.b_address.un.ip4),
                        ptp->addr_pair.b_port,
                        ptp->payload_len,
                        (char)ptp->ppayload[0],
                        (char)ptp->ppayload[1]);
            }

            return (pptph_head);
        }
        ptph_last = ptph;
    }

    /* Didn't find it, make a new one, if possible */

    // if (debug > 1)
    // {
    //     fprintf(fp_stdout, "tracing a new TCP flow\n");
    // }

    temp_ttp = NewTTP_2(pip, ptcp, plast);
    if (temp_ttp == NULL) /* not enough memory to store the new flow */
    {
        /* the new connection must begin with a SYN */
        if (debug > 0)
        {
            fprintf(fp_stdout,
                    "** out of memory when creating flows - considering a not_id_p\n");
        }
        not_id_p++;
        return (NULL);
    }

    ptph = NewPTPH_2();
    ptph->ttp_ptr = temp_ttp;
    ptph->ptp = *(ptph->ttp_ptr);

    ptph->addr_pair = ptph->ptp->addr_pair;

    /* put at the head of the access list */
    ptph->next = *pptph_head;
    *pptph_head = ptph;

    *pdir = C2S;

    /* return the new ptph */
    return (pptph_head);
}

void trace_init(void)
{
    static Bool initted = FALSE;
    extern ptp_snap **ptp_hashtable;

    if (initted)
        return;

    initted = TRUE;

    /* initialize the hash table */
    ptp_hashtable = (ptp_snap **)MallocZ(GLOBALS.Hash_Table_Size * sizeof(ptp_snap *));

    /* create an array to hold any pairs that we might create */
    ttp = (tcp_packet **)MallocZ(GLOBALS.Max_TCP_Packets * sizeof(tcp_packet *));
}

int tcp_handle(struct ip *pip, struct tcphdr *ptcp, void *plast, int *dir, struct timeval *pckt_time)
{
    ptp_snap **ptph_ptr;

    /* make sure we have enough of the packet */
    if ((unsigned long)ptcp + sizeof(struct tcphdr) - 1 > (unsigned long)plast)
    {
        if (warn_printtrunc)
            fprintf(fp_stderr,
                    "TCP packet %lu truncated too short (%ld) to trace, ignored\n",
                    pnum,
                    (unsigned long)ptcp + sizeof(struct tcphdr) -
                        (unsigned long)plast);
        return (FLOW_STAT_SHORT);
    }

    /* SYN Packet in TCP flow */
    if (SYN_SET(ptcp))
    {
        /* Copy reqired information and store it */
        ptph_ptr = FindTTP(pip, ptcp, plast, dir);
    }
    /* SYNACK or RST Packet in TCP flow*/
    else if ((SYN_SET(ptcp) && ACK_SET(ptcp)) || (RESET_SET(ptcp)))
    {
    }
    else
    {
    }

    // printf("handling TCP %ld\n", pckt_time->tv_sec);
}