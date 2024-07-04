#include "tsdn.h"

/* tcp database stats */
long not_id_p;
int search_count = 0;

extern unsigned long int fcount;
extern unsigned long int f_TCP_count;

int num_tcp_packets = -1;                  /* how many packets we've allocated */
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
NewTTP_2(struct ip *pip, struct tcphdr *ptcp, void *plast, struct timeval *pckt_time)
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
    strcpy(ptp->payload, get_ppayload(ptcp, &plast));

    ptp->arrival_time = *pckt_time;
    ptp->loc_ttp = num_tcp_packets;
    return (&ttp[num_tcp_packets]);
}

static ptp_snap *
NewPTPH_2(void)
{
    return (ptph_alloc());
}

/* connection records are stored in a hash table.  */

// ptp_snap *ptp_hashtable[HASH_TABLE_SIZE] = { NULL };
ptp_snap **ptp_hashtable;

static ptp_snap **
FindTTP(struct ip *pip, struct tcphdr *ptcp, void *plast, int *pdir)
{
    ptp_snap **pptph_cur = NULL;
    ptp_snap *ptph;

    tcp_addrblock tp_in;
    int dir;
    hash hval;

    /* grab the address from this packet */
    CopyAddr(&tp_in, pip, ntohs(ptcp->th_sport), ntohs(ptcp->th_dport));

    /* grab the hash value (already computed by CopyAddr) */
    hval = tp_in.hash % GLOBALS.Hash_Table_Size;

    // ptph_last = NULL;
    pptph_cur = &ptp_hashtable[hval];

    /* Search in the linked lists with the same hash value */
    for (ptph = *pptph_cur; ptph; ptph = ptph->next)
    {
        ++search_count;
        if (SameConn(&tp_in, &ptph->addr_pair, &dir))
        {
            /* OK, this looks good, suck it into memory */
            tcp_packet *ptp = ptph->ptp;

            /* delete: move to head of access list (unless already there) */
            // if (ptph != *pptph_head)
            // {
            //     ptph_last->next = ptph->next; /* unlink */
            //     ptph->next = *pptph_head;     /* move to head */
            //     *pptph_head = ptph;
            // }

            *pdir = dir;
            *pptph_cur = ptph;
        }
        // ptph_last = ptph;
    }

    // return the head of the access list (&ptp_hashtable[hval])
    return pptph_cur;
}

static void
UpdateTTP(tcp_packet *ptp, struct ip *pip, struct tcphdr *ptcp, void *plast, struct timeval *pckt_time)
{
    /* Update the sotred information with newly arrival packet */
    ptp->payload_len = getpayloadlength(pip, plast) - ptcp->th_off * 4;
    strcpy(ptp->payload, get_ppayload(ptcp, &plast));
    ptp->arrival_time = *pckt_time;
}

static ptp_snap *
CreateTTP(ptp_snap **pptph_head, struct ip *pip, struct tcphdr *ptcp, void *plast, struct timeval *pckt_time)
{
    static tcp_packet **temp_ttp;
    ptp_snap *ptph, **pptph_cur;

    temp_ttp = NewTTP_2(pip, ptcp, plast, pckt_time);
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

    /* return the new ptph */
    return (ptph);
}

void FreeTTP(tcp_packet *ptp_temp)
{
    int j = 0;
    hash hval;
    ptp_snap **pptph_head, **pptph_tmp;
    ptp_snap *ptph_prev, *ptph, *ptph_tmp;

    /* free up hash element->.. */
    hval = ptp_temp->addr_pair.hash % GLOBALS.Hash_Table_Size;
    pptph_head = &ptp_hashtable[hval];
    j = 0;
    ptph_prev = *pptph_head;
    for (ptph = *pptph_head; ptph; ptph = ptph->next)
    {
        j++;
        if (ptp_temp->addr_pair.hash == ptph->addr_pair.hash)
        {
            ptph_tmp = ptph;
            if (j == 1)
            {
                /* it is the top of the list */
                ptp_hashtable[hval] = ptph->next;
            }
            else
            {
                /* it is in the middle of the list */
                ptph_prev->next = ptph->next;
            }
            ptph_release(ptph_tmp);
            break;
        }
        ptph_prev = ptph;
    }
    ttp[ptp_temp->loc_ttp] = NULL;
    tp_release(ptp_temp);
}

void periodic_scanning()
{
    struct timeval tv_scan_start;
    struct timeval tv_scan_end;
    gettimeofday(&tv_scan_start, NULL);

    tcp_packet *ptp;
    int ix, dir, j;
    extern ptp_snap **ptp_hashtable;
    ptp_snap *ptph_tmp, *ptph, *ptph_prev;
    ptp_snap **pptph_head = NULL;
    double elapsed_time;
    extern host_status **active_host_hashtable;
    hash hval;
    int freed_pkt_num = 0;

    for (ix = 0; ix < GLOBALS.Max_TCP_Packets; ix += 1)
    {
        ptp = ttp[ix];
        if (ptp == NULL)
            continue;
        elapsed_time = elapsed(ptp->arrival_time, current_time) / US_PER_MS;
        if (elapsed_time > GLOBALS.TCP_Idle_Time)
        {
            hval = ptp->addr_pair.b_address.un.ip4.s_addr % GLOBALS.Hash_Table_Size;
            if (active_host_hashtable[hval] != NULL)
            {
                if (debug > 2)
                {
                    printf("packet %s at index %d expired with %.2fms, host active -> add entry to BFSW \n", inet_ntoa(ptp->addr_pair.a_address.un.ip4), ix, elapsed_time);
                    // printf("arrival_time: %ld.%ld, current_time: %ld.%ld \n",
                    //        ptp->arrival_time.tv_sec, ptp->arrival_time.tv_usec,
                    //        current_time.tv_sec, current_time.tv_usec);
                }
            }
            else
            {
                if (debug > 2)
                {
                    printf("packet %s at index %d expired with %.2fms, host inactive -> forward to honeypot \n", inet_ntoa(ptp->addr_pair.a_address.un.ip4), ix, elapsed_time);
                    // printf("arrival_time: %ld.%ld, current_time: %ld.%ld \n",
                    //        ptp->arrival_time.tv_sec, ptp->arrival_time.tv_usec,
                    //        current_time.tv_sec, current_time.tv_usec);
                }
            }
            FreeTTP(ptp);
            freed_pkt_num++;
        }
    }
    gettimeofday(&tv_scan_end, NULL);
    printf("Scanning %d and freeing %d packets in ttp cost %.5f ms \n",
           ix,
           freed_pkt_num,
           (double)(tv_scan_end.tv_usec - tv_scan_start.tv_usec) / US_PER_MS);
}

void UpdateActiveHost(struct ip *pip, struct timeval *pckt_time)
{
    /* Only update when src host of a SYNACK/RST packet is internal */
    if (!internal_ip(pip->ip_src))
        return;

    extern host_status **active_host_hashtable;
    host_status **pphosth;
    host_status *new_phost;
    hash hval;

    /* Here we just use ip_address to calculate hash */
    hval = pip->ip_src.s_addr % GLOBALS.Hash_Table_Size;
    pphosth = &active_host_hashtable[hval];

    if (*pphosth == NULL)
    {
        new_phost = (host_status *)MMmalloc(sizeof(host_status), "UpdateActiveHost");
        /* not considering the hash conflict temporaily, since hash table is big enough */
        *pphosth = new_phost;
        (*pphosth)->hval = hval;
        (*pphosth)->ip_addr.addr_vers = 4;
        (*pphosth)->ip_addr.un.ip4 = pip->ip_src;
        (*pphosth)->last_time = (*pckt_time);
    }
    else
    {
        (*pphosth)->last_time = (*pckt_time);
    }
}

// Bool FindActiveHost(struct ip *pip)
// {
//     extern host_status **active_host_hashtable;
//     hash hval = pip->ip_src.s_addr % GLOBALS.Hash_Table_Size;
//     return ((active_host_hashtable[hval] != NULL));
// }

int tcp_handle(struct ip *pip, struct tcphdr *ptcp, void *plast, int *dir, struct timeval *pckt_time)
{
    ptp_snap **ptph_ptr;
    ptp_snap **pptph_head, **pptph_tmp;
    ptp_snap *ptph, *ptph_prev, *ptph_tmp;
    tcp_packet *ptp_temp;
    int new_tcp_flow = 1;

    char ip_src_addr_print_buffer[INET_ADDRSTRLEN], ip_dst_addr_print_buffer[INET_ADDRSTRLEN];
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

    periodic_scanning();

    /* SYN Packet in TCP flow */
    if (SYN_SET(ptcp) && !ACK_SET(ptcp))
    {
        ptph_ptr = FindTTP(pip, ptcp, plast, dir);
        if (*ptph_ptr != NULL)
        {
            if ((*ptph_ptr)->ptp != NULL)
            {
                /* Found it, update it */
                new_tcp_flow = 0;
                ptp_temp = (*ptph_ptr)->ptp;
                UpdateTTP(ptp_temp, pip, ptcp, plast, pckt_time);
                if (debug > 2)
                {
                    inet_ntop(AF_INET, &ptp_temp->addr_pair.a_address.un.ip4, ip_src_addr_print_buffer, INET_ADDRSTRLEN);
                    inet_ntop(AF_INET, &ptp_temp->addr_pair.b_address.un.ip4, ip_dst_addr_print_buffer, INET_ADDRSTRLEN);
                    fprintf(fp_stdout, "SYN already exists: from %s:%d to %s:%d with %d bytes of payload %c%c... at %ld\n",
                            ip_src_addr_print_buffer,
                            ptp_temp->addr_pair.a_port,
                            ip_dst_addr_print_buffer,
                            ptp_temp->addr_pair.b_port,
                            ptp_temp->payload_len,
                            ptp_temp->payload[0],
                            ptp_temp->payload[1],
                            ptp_temp->arrival_time.tv_sec);
                }
            }
        }
        if (new_tcp_flow)
        {
            /* Didn't find it, make a new one, if possible */
            ptph_tmp = CreateTTP(ptph_ptr, pip, ptcp, plast, pckt_time);
            if (debug > 3)
            {
                ptp_temp = ptph_tmp->ptp;
                inet_ntop(AF_INET, &ptp_temp->addr_pair.a_address.un.ip4, ip_src_addr_print_buffer, INET_ADDRSTRLEN);
                inet_ntop(AF_INET, &ptp_temp->addr_pair.b_address.un.ip4, ip_dst_addr_print_buffer, INET_ADDRSTRLEN);
                fprintf(fp_stdout, "new TCP SYN stored: from %s:%d to %s:%d with %d bytes of payload %c%c.. at %ld\n",
                        ip_src_addr_print_buffer,
                        ptp_temp->addr_pair.a_port,
                        ip_dst_addr_print_buffer,
                        ptp_temp->addr_pair.b_port,
                        ptp_temp->payload_len,
                        ptp_temp->payload[0],
                        ptp_temp->payload[1],
                        ptp_temp->arrival_time.tv_sec);
            }
        }
    }
    /* SYNACK or RST Packet in TCP flow*/
    else if ((SYN_SET(ptcp) && ACK_SET(ptcp)) || (RESET_SET(ptcp)))
    {
        ptph_ptr = FindTTP(pip, ptcp, plast, dir);
        /* Found SYN */
        if (*ptph_ptr != NULL)
        {
            if ((ptp_temp = (*ptph_ptr)->ptp) != NULL)
            {
                /* Only reversed direction is correct SYN */
                if ((*dir) == S2C)
                {
                    if (debug > 2)
                    {
                        inet_ntop(AF_INET, &ptp_temp->addr_pair.a_address.un.ip4, ip_src_addr_print_buffer, INET_ADDRSTRLEN);
                        inet_ntop(AF_INET, &ptp_temp->addr_pair.b_address.un.ip4, ip_dst_addr_print_buffer, INET_ADDRSTRLEN);
                        fprintf(fp_stdout, "found corresponding SYN: from %s:%d to %s:%d with %d bytes of payload %c%c.. at %ld\n",
                                ip_src_addr_print_buffer,
                                ptp_temp->addr_pair.a_port,
                                ip_dst_addr_print_buffer,
                                ptp_temp->addr_pair.b_port,
                                ptp_temp->payload_len,
                                ptp_temp->payload[0],
                                ptp_temp->payload[1],
                                ptp_temp->arrival_time.tv_sec);
                    }
                    FreeTTP(ptp_temp);
                    new_tcp_flow = 0;
                }
            }
        }
        /* A SYNACK without observed SYN */
        if (new_tcp_flow)
        {
            if (debug > 2)
            {
                inet_ntop(AF_INET, &pip->ip_src, ip_src_addr_print_buffer, INET_ADDRSTRLEN);
                inet_ntop(AF_INET, &pip->ip_dst, ip_dst_addr_print_buffer, INET_ADDRSTRLEN);
                fprintf(fp_stdout, "no corresponding SYN for SYNACK: from %s:%d to %s:%d\n",
                        ip_src_addr_print_buffer,
                        ntohs(ptcp->th_sport),
                        ip_dst_addr_print_buffer,
                        ntohs(ptcp->th_sport));
            }
        }
        UpdateActiveHost(pip, pckt_time);
    }
    else
    {
    }

    if (debug > 1)
    {
        print_ttp();
    }
}

void trace_init(void)
{
    static Bool initted = FALSE;
    extern ptp_snap **ptp_hashtable;
    extern host_status **active_host_hashtable;

    if (initted)
        return;

    initted = TRUE;

    /* initialize the hash table */
    ptp_hashtable = (ptp_snap **)MallocZ(GLOBALS.Hash_Table_Size * sizeof(ptp_snap *));
    active_host_hashtable = (host_status **)MallocZ(GLOBALS.Hash_Table_Size * sizeof(host_status *));

    /* create an array to hold any pairs that we might create */
    ttp = (tcp_packet **)MallocZ(GLOBALS.Max_TCP_Packets * sizeof(tcp_packet *));
}

/* Helper functions */
void print_ttp()
{
    int p;

    for (p = 0; p < 20; p++)
    {
        fprintf(fp_stdout, "[%2d]", p);
        if (ttp[p] != NULL)
            fprintf(fp_stdout, "->[ptp] src_ip: %s src_port: %d \n", inet_ntoa(ttp[p]->addr_pair.a_address.un.ip4), ttp[p]->addr_pair.a_port);
        else
            fprintf(fp_stdout, "->[NULL]\n");
    }
}

void free_packets(int free_num)
{
    struct timeval tv_scan_start;
    struct timeval tv_scan_end;
    gettimeofday(&tv_scan_start, NULL);

    tcp_packet *ptp;
    int ix, dir, j;
    extern ptp_snap **ptp_hashtable;
    ptp_snap *ptph_tmp, *ptph, *ptph_prev;
    ptp_snap **pptph_head = NULL;
    double elapsed_time;
    extern host_status **active_host_hashtable;
    hash hval;
    int freed_pkt_num = 0;

    for (ix = 0; ix < GLOBALS.Max_TCP_Packets; ix += 1)
    {
        ptp = ttp[ix];
        if (ptp == NULL)
            continue;
        elapsed_time = elapsed(ptp->arrival_time, current_time) / US_PER_MS;
        if (elapsed_time > GLOBALS.TCP_Idle_Time)
        {
            hval = ptp->addr_pair.b_address.un.ip4.s_addr % GLOBALS.Hash_Table_Size;
            if (active_host_hashtable[hval] != NULL)
            {
                // if (debug > 2)
                // {
                //     printf("packet %s at index %d expired with %.2fms, host active -> add entry to BFSW \n", inet_ntoa(ptp->addr_pair.a_address.un.ip4), ix, elapsed_time);
                //     // printf("arrival_time: %ld.%ld, current_time: %ld.%ld \n",
                //     //        ptp->arrival_time.tv_sec, ptp->arrival_time.tv_usec,
                //     //        current_time.tv_sec, current_time.tv_usec);
                // }
            }
            else
            {
                // if (debug > 2)
                // {
                //     printf("packet %s at index %d expired with %.2fms, host inactive -> forward to honeypot \n", inet_ntoa(ptp->addr_pair.a_address.un.ip4), ix, elapsed_time);
                //     // printf("arrival_time: %ld.%ld, current_time: %ld.%ld \n",
                //     //        ptp->arrival_time.tv_sec, ptp->arrival_time.tv_usec,
                //     //        current_time.tv_sec, current_time.tv_usec);
                // }
            }
            FreeTTP(ptp);
            freed_pkt_num++;
        }
        else
        {
            FreeTTP(ptp);
            freed_pkt_num++;
        }
    }
    gettimeofday(&tv_scan_end, NULL);
    printf("Scanning %d and freeing %d packets in ttp cost %.5f ms \n",
           ix,
           freed_pkt_num,
           (double)(tv_scan_end.tv_usec - tv_scan_start.tv_usec) / US_PER_MS);
}