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

/* connection records are stored in a hash table.  */

// ptp_snap *ptp_hashtable[HASH_TABLE_SIZE] = { NULL };
ptp_snap **ptp_hashtable;
flow_hash **flow_hash_table;

pkt_desc_t **pkt_desc_buf;
circular_buf_t *circ_buf;

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

static tcp_packet *
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
    return ttp[num_tcp_packets];
}

static ptp_snap *
NewPTPH_2(void)
{
    return (ptph_alloc());
}

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

            *pdir = dir;
            *pptph_cur = ptph;
        }
        // ptph_last = ptph;
    }

    // return the head of the access list (&ptp_hashtable[hval])
    return pptph_cur;
}

static flow_hash *
FindFlowHash(struct ip *pip, struct tcphdr *ptcp, void *plast, int *pdir)
{
    tcp_addrblock tp_in;
    int dir;
    hash hval;
    flow_hash *flow_hash_ptr;

    /* grab the address from this packet */
    CopyAddr(&tp_in, pip, ntohs(ptcp->th_sport), ntohs(ptcp->th_dport));

    /* grab the hash value (already computed by CopyAddr) */
    hval = tp_in.hash % GLOBALS.Hash_Table_Size;

    /* Search in the linked lists with the same hash value */
    for (flow_hash_ptr = flow_hash_table[hval]; flow_hash_ptr; flow_hash_ptr = flow_hash_ptr->next)
    {
        if (SameConn(&tp_in, &flow_hash_ptr->addr_pair, &dir))
        {
            /* Found */
            *pdir = dir;
            return flow_hash_ptr;
        }
    }
    /* Not found */
    return NULL;
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
    static tcp_packet *temp_ttp;
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
    // ptph->ttp_ptr = temp_ttp;
    ptph->ptp = temp_ttp;
    ptph->addr_pair = ptph->ptp->addr_pair;

    /* put at the head of the access list */
    ptph->next = *pptph_head;
    *pptph_head = ptph;

    /* return the new ptph */
    return (ptph);
}

static flow_hash *CreateFlowHash(struct ip *pip, struct tcphdr *ptcp, void *plast, struct timeval *pckt_time)
{
    static tcp_packet *temp_ttp;
    pkt_desc_t *temp_pkt_desc_ptr;
    flow_hash *temp_flow_hash_ptr;
    flow_hash **flow_hash_head_pp;
    hash hval;

    temp_ttp = NewTTP_2(pip, ptcp, plast, pckt_time);
    if (temp_ttp == NULL) /* not enough memory to store the new flow */
    {
        if (debug > 0)
        {
            fprintf(fp_stdout,
                    "** out of memory when creating flows - considering a not_id_p\n");
        }
        not_id_p++;
        return (NULL);
    }

    /* grab the hash value (already computed by CopyAddr) */
    hval = temp_ttp->addr_pair.hash % GLOBALS.Hash_Table_Size;
    flow_hash_head_pp = &flow_hash_table[hval];

    temp_pkt_desc_ptr = pkt_desc_alloc();
    temp_pkt_desc_ptr->pkt_ptr = temp_ttp;
    temp_pkt_desc_ptr->recv_time = *pckt_time;
    if (!circular_buf_try_put(circ_buf, temp_pkt_desc_ptr))
    {
        fprintf(fp_stderr, "Error: Circular buffer is full\n");
        return NULL;
    }
    temp_flow_hash_ptr = flow_hash_alloc();
    temp_flow_hash_ptr->addr_pair = temp_ttp->addr_pair;
    temp_flow_hash_ptr->pkt_desc = temp_pkt_desc_ptr;

    temp_flow_hash_ptr->next = *flow_hash_head_pp;
    *flow_hash_head_pp = temp_flow_hash_ptr;

    return temp_flow_hash_ptr;
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

void FreeFlowHash(flow_hash *flow_hash_ptr)
{
    int j = 0;
    hash hval;
    pkt_desc_t *pkt_desc_ptr;
    flow_hash *flow_hash_head_ptr, *flow_hash_prev, *temp_flow_hash_ptr;

    pkt_desc_ptr = flow_hash_ptr->pkt_desc;
    hval = flow_hash_ptr->addr_pair.hash % GLOBALS.Hash_Table_Size;
    flow_hash_head_ptr = flow_hash_table[hval];

    flow_hash_prev = flow_hash_head_ptr;
    for (temp_flow_hash_ptr = flow_hash_head_ptr; temp_flow_hash_ptr; temp_flow_hash_ptr = temp_flow_hash_ptr->next)
    {
        j++;
        if (flow_hash_ptr->addr_pair.hash == temp_flow_hash_ptr->addr_pair.hash)
        {
            if (j == 1)
            {
                /* it is the top of the linked list */
                flow_hash_table[hval] = temp_flow_hash_ptr->next;
            }
            else
            {
                /* it is in the middle of the linked list */
                flow_hash_prev->next = temp_flow_hash_ptr->next;
            }
            pkt_desc_release(pkt_desc_ptr);
            flow_hash_release(flow_hash_ptr);
            break;
        }
        flow_hash_prev = temp_flow_hash_ptr;
    }
}

int tcp_handle(struct ip *pip, struct tcphdr *ptcp, void *plast, int *dir, struct timeval *pckt_time)
{
    flow_hash *flow_hash_ptr;
    pkt_desc_t *pkt_desc_ptr;

    // use two string buffer for print the IP address transformed from inet_ntop
    char ip_src_addr_print_buffer[INET_ADDRSTRLEN], ip_dst_addr_print_buffer[INET_ADDRSTRLEN];

    /* SYN Packet in TCP flow */
    if (SYN_SET(ptcp) && !ACK_SET(ptcp))
    {
        flow_hash_ptr = FindFlowHash(pip, ptcp, plast, dir);
        if (flow_hash_ptr != NULL)
        {
            if (debug > 1)
            {
                inet_ntop(AF_INET, &(flow_hash_ptr->addr_pair.a_address.un.ip4), ip_src_addr_print_buffer, INET_ADDRSTRLEN);
                inet_ntop(AF_INET, &(flow_hash_ptr->addr_pair.b_address.un.ip4), ip_dst_addr_print_buffer, INET_ADDRSTRLEN);
                fprintf(fp_stdout, "found TCP SYN: from %s:%d to %s:%d with %d bytes of payload %c%c.. at %ld\n",
                        ip_src_addr_print_buffer,
                        flow_hash_ptr->addr_pair.a_port,
                        ip_dst_addr_print_buffer,
                        flow_hash_ptr->addr_pair.b_port,
                        flow_hash_ptr->pkt_desc->pkt_ptr->payload_len,
                        flow_hash_ptr->pkt_desc->pkt_ptr->payload[0],
                        flow_hash_ptr->pkt_desc->pkt_ptr->payload[1],
                        flow_hash_ptr->pkt_desc->recv_time.tv_sec);
            }
        }
        else
        {
            flow_hash_ptr = CreateFlowHash(pip, ptcp, plast, pckt_time);
            if (debug > 1)
            {
                inet_ntop(AF_INET, &(flow_hash_ptr->addr_pair.a_address.un.ip4), ip_src_addr_print_buffer, INET_ADDRSTRLEN);
                inet_ntop(AF_INET, &(flow_hash_ptr->addr_pair.b_address.un.ip4), ip_dst_addr_print_buffer, INET_ADDRSTRLEN);
                fprintf(fp_stdout, "new TCP SYN stored: from %s:%d to %s:%d with %d bytes of payload %c%c.. at %ld\n",
                        ip_src_addr_print_buffer,
                        flow_hash_ptr->addr_pair.a_port,
                        ip_dst_addr_print_buffer,
                        flow_hash_ptr->addr_pair.b_port,
                        flow_hash_ptr->pkt_desc->pkt_ptr->payload_len,
                        flow_hash_ptr->pkt_desc->pkt_ptr->payload[0],
                        flow_hash_ptr->pkt_desc->pkt_ptr->payload[1],
                        flow_hash_ptr->pkt_desc->recv_time.tv_sec);
            }
        }
    }
    else if ((SYN_SET(ptcp) && ACK_SET(ptcp)) || (RESET_SET(ptcp)))
    {
        flow_hash_ptr = FindFlowHash(pip, ptcp, plast, dir);
        if (flow_hash_ptr != NULL)
        {
            if (debug > 1)
            {
                inet_ntop(AF_INET, &(flow_hash_ptr->addr_pair.a_address.un.ip4), ip_src_addr_print_buffer, INET_ADDRSTRLEN);
                inet_ntop(AF_INET, &(flow_hash_ptr->addr_pair.b_address.un.ip4), ip_dst_addr_print_buffer, INET_ADDRSTRLEN);
                fprintf(fp_stdout, "freeing TCP SYN!!! from %s:%d to %s:%d with %d bytes of payload %c%c.. at %ld\n",
                        ip_src_addr_print_buffer,
                        flow_hash_ptr->addr_pair.a_port,
                        ip_dst_addr_print_buffer,
                        flow_hash_ptr->addr_pair.b_port,
                        flow_hash_ptr->pkt_desc->pkt_ptr->payload_len,
                        flow_hash_ptr->pkt_desc->pkt_ptr->payload[0],
                        flow_hash_ptr->pkt_desc->pkt_ptr->payload[1],
                        flow_hash_ptr->pkt_desc->recv_time.tv_sec);
            }
            FreeFlowHash(flow_hash_ptr);
        }
    }
}

/* timeout_mgmt thread */
void *timeout_mgmt(void *args)
{
    pkt_desc_t **pkt_desc_ptr_ptr;

    while (1)
    {
        if (circular_buf_get(circ_buf, pkt_desc_ptr_ptr))
        {
            /* The packet descriptor has been freed. */
            if (pkt_desc_ptr_ptr == NULL)
            {
                fprintf(fp_stderr, "pkt_desc_ptr_ptr is NULL\n");
                continue;
            }
            else
            {
                if (debug > 1)
                {
                    char ip_src_addr_print_buffer[INET_ADDRSTRLEN], ip_dst_addr_print_buffer[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &((*pkt_desc_ptr_ptr)->pkt_ptr->addr_pair.a_address.un.ip4), ip_src_addr_print_buffer, INET_ADDRSTRLEN);
                    inet_ntop(AF_INET, &((*pkt_desc_ptr_ptr)->pkt_ptr->addr_pair.b_address.un.ip4), ip_dst_addr_print_buffer, INET_ADDRSTRLEN);
                    fprintf(fp_stdout, "popping TCP SYN: from %s:%d to %s:%d with %d bytes of payload %c%c.. at %ld\n",
                            ip_src_addr_print_buffer,
                            (*pkt_desc_ptr_ptr)->pkt_ptr->addr_pair.a_port,
                            ip_dst_addr_print_buffer,
                            (*pkt_desc_ptr_ptr)->pkt_ptr->addr_pair.b_port,
                            (*pkt_desc_ptr_ptr)->pkt_ptr->payload_len,
                            (*pkt_desc_ptr_ptr)->pkt_ptr->payload[0],
                            (*pkt_desc_ptr_ptr)->pkt_ptr->payload[1],
                            (*pkt_desc_ptr_ptr)->recv_time.tv_sec);
                }
            }

            // printf("size: %ld \n", circular_buf_size(circ_buf));
        }
        else
        {
            printf("Error: Circular buffer is empty\n");
        }
        usleep(GLOBALS.TCP_Idle_Time * US_PER_MS);
    }
}

void trace_init(void)
{
    static Bool initted = FALSE;
    extern ptp_snap **ptp_hashtable;
    // extern host_status **active_host_hashtable;

    if (initted)
        return;

    initted = TRUE;

    /* initialize the hash table */
    ptp_hashtable = (ptp_snap **)MallocZ(GLOBALS.Hash_Table_Size * sizeof(ptp_snap *));

    /* create an array to hold any pairs that we might create */
    ttp = (tcp_packet **)MallocZ(GLOBALS.Max_TCP_Packets * sizeof(tcp_packet *));

    /* initalize the packet descriptor buffer for the circular buffer */
    pkt_desc_buf = (pkt_desc_t **)MallocZ(GLOBALS.Max_TCP_Packets * sizeof(pkt_desc_t *));

    /* initalize the circular buffer */
    circ_buf = circular_buf_init(pkt_desc_buf, GLOBALS.Max_TCP_Packets);

    /* initialize the hash table */
    flow_hash_table = (flow_hash **)MallocZ(GLOBALS.Hash_Table_Size * sizeof(flow_hash *));
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
