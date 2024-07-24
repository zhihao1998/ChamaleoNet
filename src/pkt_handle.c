#include "tsdn.h"

/* tcp database stats */
long not_id_p;
int search_count = 0;

extern unsigned long int fcount;
extern unsigned long int f_TCP_count;

int num_ip_packets = -1;    /* how many packets we've allocated */
ip_packet **pkt_arr = NULL; /* array of pointers to allocated packets */

Bool warn_MAX_ = TRUE;

static pthread_mutex_t g_tMutex;
static pthread_cond_t cond;

/* connection records are stored in a hash table.  */
flow_hash **flow_hash_table;

pkt_desc_t **pkt_desc_buf;
circular_buf_t *circ_buf;

/* copy the IP addresses and port numbers into an addrblock structure	*/
/* in addition to copying the address, we also create a HASH value	*/
/* which is based on BOTH IP addresses and port numbers.  It allows	*/
/* faster comparisons most of the time					*/
void CopyAddr(flow_addrblock *p_flow_addr, struct ip *pip, void *p_l4_hdr)
{
    p_flow_addr->protocol = pip->ip_p;
    switch (pip->ip_p)
    {
        /* TODO: ICMP is different! */
    case IPPROTO_ICMP:
    {
        p_flow_addr->a_port = ((icmphdr *)p_l4_hdr)->type;
        p_flow_addr->b_port = ((icmphdr *)p_l4_hdr)->code;
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

static ip_packet *
NewPkt(struct ether_header *peth, struct ip *pip, void *ptcp, void *plast, struct timeval *pckt_time)
{
    ip_packet *ppkt;
    int old_new_ip_packets = num_ip_packets;
    int steps = 0;

    /* look for the next eventually available free block */
    num_ip_packets++;
    num_ip_packets = num_ip_packets % GLOBALS.Max_TCP_Packets;

    /* make a new one, if possible */
    while ((num_ip_packets != old_new_ip_packets) && (pkt_arr[num_ip_packets] != NULL) && (steps < GLOBALS.List_Search_Dept))
    {
        steps++;
        /* look for the next one */
        //         fprintf (fp_stdout, "%d %d\n", num_tcp_pairs, old_new_tcp_pairs);
        num_ip_packets++;
        num_ip_packets = num_ip_packets % GLOBALS.Max_TCP_Packets;
    }
    if (pkt_arr[num_ip_packets] != NULL)
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
    ppkt = pkt_arr[num_ip_packets] = pkt_alloc();

    /* grab the address from this packet */
    CopyAddr(&ppkt->addr_pair, pip, ptcp);

    ppkt->internal_src = internal_src;
    ppkt->internal_dst = internal_dst;

    /* Here we store raw packets starting from Ether header */
    ppkt->pkt_len = ntohs(pip->ip_len) + ETHER_HDR_LEN;
    memcpy(ppkt->raw_pkt, peth, ppkt->pkt_len);
    ppkt->loc_pkt_arr = num_ip_packets;
    return pkt_arr[num_ip_packets];
}

static flow_hash *
FindFlowHash(struct ip *pip, void *ptcp, void *plast, int *pdir)
{
    flow_addrblock pkt_in;
    hash hval;
    flow_hash *flow_hash_ptr;

    /* grab the address from this packet */
    CopyAddr(&pkt_in, pip, ptcp);

    /* grab the hash value (already computed by CopyAddr) */
    hval = pkt_in.hash % GLOBALS.Hash_Table_Size;

    /* Search in the linked lists with the same hash value */
    for (flow_hash_ptr = flow_hash_table[hval]; flow_hash_ptr; flow_hash_ptr = flow_hash_ptr->next)
    {
        if (SameConn(&pkt_in, &flow_hash_ptr->addr_pair, pdir))
        {
            /* Found */
            return flow_hash_ptr;
        }
    }
    /* Not found */
    return NULL;
}

static flow_hash *CreateFlowHash(struct ether_header *peth, struct ip *pip, void *ptcp, void *plast, struct timeval *pckt_time)
{
    static ip_packet *temp_pkt;
    pkt_desc_t *temp_pkt_desc_ptr;
    pkt_desc_t **temp_pkt_desc_pp;
    flow_hash *temp_flow_hash_ptr;
    flow_hash **flow_hash_head_pp;
    hash hval;

    temp_pkt = NewPkt(peth, pip, ptcp, plast, pckt_time);
    if (temp_pkt == NULL) /* not enough memory to store the new flow */
    {
        if (debug > 0)
        {
            fprintf(fp_stdout,
                    "** out of memory when creating flows - considering a not_id_p\n");
        }
        not_id_p++;
        return (NULL);
    }

    hval = temp_pkt->addr_pair.hash % GLOBALS.Hash_Table_Size;
    flow_hash_head_pp = &flow_hash_table[hval];

    temp_pkt_desc_ptr = pkt_desc_alloc();
    temp_pkt_desc_ptr->pkt_ptr = temp_pkt;
    temp_pkt_desc_ptr->recv_time = *pckt_time;

    temp_pkt_desc_pp = circular_buf_try_put(circ_buf, temp_pkt_desc_ptr);
    if (temp_pkt_desc_pp == NULL)
    {
        fprintf(fp_stderr, "Error: Circular buffer is full\n");
        return NULL;
    }
    temp_flow_hash_ptr = flow_hash_alloc();
    temp_flow_hash_ptr->addr_pair = temp_pkt->addr_pair;
    temp_flow_hash_ptr->pkt_desc_ptr = temp_pkt_desc_ptr;
    temp_flow_hash_ptr->pkt_desc_ptr_ptr = temp_pkt_desc_pp;

    temp_flow_hash_ptr->next = *flow_hash_head_pp;
    *flow_hash_head_pp = temp_flow_hash_ptr;
    return temp_flow_hash_ptr;
}

void FreePkt(ip_packet *ppkt_temp)
{
    pkt_arr[ppkt_temp->loc_pkt_arr] = NULL;
    pkt_release(ppkt_temp);
}

void FreeFlowHash(flow_hash *flow_hash_ptr)
{
    int j = 0;
    hash hval;
    pkt_desc_t *pkt_desc_ptr;
    flow_hash *flow_hash_head_ptr, *flow_hash_prev, *temp_flow_hash_ptr;

    pkt_desc_ptr = flow_hash_ptr->pkt_desc_ptr;

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
            *(flow_hash_ptr->pkt_desc_ptr_ptr) = NULL;
            flow_hash_release(flow_hash_ptr);
            break;
        }
        flow_hash_prev = temp_flow_hash_ptr;
    }
}

int pkt_handle(struct ether_header *peth, struct ip *pip, void *ptcp, void *plast, struct timeval *pckt_time)
{
    flow_hash *flow_hash_ptr;
    pkt_desc_t *pkt_desc_ptr;
    int dir = 0;

    // struct ether_addr *eth_addr;
    // fprintf(fp_stdout, "Ethernet Frame: %s",
    //         ether_ntoa((struct ether_addr *)peth->ether_shost));
    // fprintf(fp_stdout, "->%s\n",
    //         ether_ntoa((struct ether_addr *)peth->ether_dhost));

    // use two string buffer for print the IP address transformed from inet_ntop
    char ip_src_addr_print_buffer[INET_ADDRSTRLEN], ip_dst_addr_print_buffer[INET_ADDRSTRLEN];

    /* do not rely on the header, instead check if it's already in the hash table */
    flow_hash_ptr = FindFlowHash(pip, ptcp, plast, &dir);
    /* Found the flow, then check the direction of this packet */
    if (flow_hash_ptr != NULL)
    {
        /* Same direction of this packet, probably another reply */
        if (dir == C2S)
        {
            if (debug > 1)
            {
                inet_ntop(AF_INET, &(flow_hash_ptr->addr_pair.a_address.un.ip4), ip_src_addr_print_buffer, INET_ADDRSTRLEN);
                inet_ntop(AF_INET, &(flow_hash_ptr->addr_pair.b_address.un.ip4), ip_dst_addr_print_buffer, INET_ADDRSTRLEN);
                fprintf(fp_stdout, "tcp_handle: C2S: from %s:%d to %s:%d with %d bytes of raw_packet %c%c.. at %ld\n",
                        ip_src_addr_print_buffer,
                        flow_hash_ptr->addr_pair.a_port,
                        ip_dst_addr_print_buffer,
                        flow_hash_ptr->addr_pair.b_port,
                        flow_hash_ptr->pkt_desc_ptr->pkt_ptr->pkt_len,
                        flow_hash_ptr->pkt_desc_ptr->pkt_ptr->raw_pkt[0],
                        flow_hash_ptr->pkt_desc_ptr->pkt_ptr->raw_pkt[1],
                        flow_hash_ptr->pkt_desc_ptr->recv_time.tv_sec);
            }
        }
        /* Reversed direction of this packet, probably a response */
        else if (dir == S2C)
        {
            if (debug > 1)
            {
                inet_ntop(AF_INET, &(flow_hash_ptr->addr_pair.a_address.un.ip4), ip_src_addr_print_buffer, INET_ADDRSTRLEN);
                inet_ntop(AF_INET, &(flow_hash_ptr->addr_pair.b_address.un.ip4), ip_dst_addr_print_buffer, INET_ADDRSTRLEN);
                fprintf(fp_stdout, "tcp_handle: S2C: from %s:%d to %s:%d with %d bytes of raw_packet %c%c.. at %ld\n",
                        ip_src_addr_print_buffer,
                        flow_hash_ptr->addr_pair.a_port,
                        ip_dst_addr_print_buffer,
                        flow_hash_ptr->addr_pair.b_port,
                        flow_hash_ptr->pkt_desc_ptr->pkt_ptr->pkt_len,
                        flow_hash_ptr->pkt_desc_ptr->pkt_ptr->raw_pkt[0],
                        flow_hash_ptr->pkt_desc_ptr->pkt_ptr->raw_pkt[1],
                        flow_hash_ptr->pkt_desc_ptr->recv_time.tv_sec);
            }

            /* TODO: should we lock this? */
            FreePkt(flow_hash_ptr->pkt_desc_ptr->pkt_ptr);
            FreeFlowHash(flow_hash_ptr);
        }
    }
    /* Didn't find the flow, create one */
    else
    {
        flow_hash_ptr = CreateFlowHash(peth, pip, ptcp, plast, pckt_time);

        /* Calculate the packet processing time */
        // timeval current_time, pkt_time;
        // int time_diff;
        // pkt_time = flow_hash_ptr->pkt_desc_ptr->recv_time;
        // gettimeofday(&current_time, NULL);
        // time_diff = tv_sub_2(current_time, pkt_time);
        // fprintf(fp_stdout, "PKT_RX: cur_time - pkt_time =  %dus!\n", time_diff);

        /* Weak up the timeout_mgmt thread */
        if (!circular_buf_empty(circ_buf))
        {
            pthread_cond_signal(&cond);
        }
        if (debug > 1)
        {
            inet_ntop(AF_INET, &(flow_hash_ptr->addr_pair.a_address.un.ip4), ip_src_addr_print_buffer, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &(flow_hash_ptr->addr_pair.b_address.un.ip4), ip_dst_addr_print_buffer, INET_ADDRSTRLEN);
            fprintf(fp_stdout, "PKT_RX: new TCP SYN stored: from %s:%d to %s:%d with %d bytes of raw_packet %s at %ld.%5ld\n",
                    ip_src_addr_print_buffer,
                    ntohs(flow_hash_ptr->addr_pair.a_port),
                    ip_dst_addr_print_buffer,
                    ntohs(flow_hash_ptr->addr_pair.b_port),
                    flow_hash_ptr->pkt_desc_ptr->pkt_ptr->pkt_len,
                    ether_ntoa((struct ether_addr *)flow_hash_ptr->pkt_desc_ptr->pkt_ptr->raw_pkt),
                    // inet_ntoa(*(struct in_addr *)(flow_hash_ptr->pkt_desc_ptr->pkt_ptr->raw_pkt + 26)),
                    flow_hash_ptr->pkt_desc_ptr->recv_time.tv_sec,
                    flow_hash_ptr->pkt_desc_ptr->recv_time.tv_usec);
        }
    }
}

/* timeout_mgmt thread */
void *timeout_mgmt(void *args)
{
    while (circular_buf_empty(circ_buf))
    {
        fprintf(fp_stdout, "TIMEOUT_MGMT: Circular Buffer empty, thread blocked!\n");
        pthread_cond_wait(&cond, &g_tMutex);
    }
    pkt_desc_t *pkt_desc_ptr;
    hash hval;
    flow_hash *flow_hash_ptr;
    int dir;
    flow_addrblock pkt_in;
    Bool is_found;
    timeval current_time, pkt_time;
    int sleep_time_us, time_diff;

    while (1)
    {
        fprintf(fp_stderr, "TIMEOUT_MGMT: size: %ld!\n", circular_buf_size(circ_buf));
        if (circular_buf_size(circ_buf) == 0)
        {
            fprintf(fp_stdout, "TIMEOUT_MGMT: Circular Buffer empty, thread blocked!\n");
            pthread_cond_wait(&cond, &g_tMutex);
        }

        /* Check the next timeout */
        if (circular_buf_get(circ_buf, &pkt_desc_ptr) != -1)
        {
            /* The packet is freed before the sleep */
            if ((pkt_desc_ptr == NULL) || (pkt_desc_ptr->pkt_ptr == NULL))
            {
                fprintf(fp_stdout, "TIMEOUT_MGMT: Before sleeping skipped a packet descriptor which has already been freed.\n");
                continue;
            }
            else
            {
                /* Sleeping time calculation */
                pkt_time = pkt_desc_ptr->recv_time;
                gettimeofday(&current_time, NULL);
                time_diff = tv_sub_2(current_time, pkt_time);
                /* if (cur_time – pkt_time) <= Timeout, sleeps for (Timeout - (cur_time – pkt_time)) */
                if (GLOBALS.TCP_Idle_Time >= time_diff)
                {
                    sleep_time_us = GLOBALS.TCP_Idle_Time - time_diff;
                    if (debug > 1)
                    {
                        fprintf(fp_stdout, "TIMEOUT_MGMT: going to sleep for %dus!\n", sleep_time_us);
                    }
                    usleep(sleep_time_us);
                }
                /* otherwise, the packet is delayed more than Timeout. The packet should to be freed immediately.
                 * Should try to not let this happen! */
                else
                {
                    if (debug > 1)
                    {
                        fprintf(fp_stderr, "TIMEOUT_MGMT: A packet is delayed too long for %dus!!!\n", time_diff);
                    }
                }

                /* sleeping finishes, start cleaning */
                /* The packet could be freed during the sleeping, so we should check again after sleeping */
                if ((pkt_desc_ptr == NULL) || (pkt_desc_ptr->pkt_ptr == NULL))
                {
                    fprintf(fp_stdout, "TIMEOUT_MGMT: After sleeping skipped a packet descriptor which has already been freed.\n");
                    continue;
                }

                is_found = FALSE;
                /* The packet descriptor has been freed. */
                if (debug > 1)
                {
                    char ip_src_addr_print_buffer[INET_ADDRSTRLEN], ip_dst_addr_print_buffer[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &((pkt_desc_ptr)->pkt_ptr->addr_pair.a_address.un.ip4), ip_src_addr_print_buffer, INET_ADDRSTRLEN);
                    inet_ntop(AF_INET, &((pkt_desc_ptr)->pkt_ptr->addr_pair.b_address.un.ip4), ip_dst_addr_print_buffer, INET_ADDRSTRLEN);
                    fprintf(fp_stdout, "TIMEOUT_MGMT: popping TCP SYN: from %s:%d to %s:%d with %d bytes of raw packet %c%c.. at %ld.%5ld\n",
                            ip_src_addr_print_buffer,
                            (pkt_desc_ptr)->pkt_ptr->addr_pair.a_port,
                            ip_dst_addr_print_buffer,
                            (pkt_desc_ptr)->pkt_ptr->addr_pair.b_port,
                            (pkt_desc_ptr)->pkt_ptr->pkt_len,
                            (pkt_desc_ptr)->pkt_ptr->raw_pkt[0],
                            (pkt_desc_ptr)->pkt_ptr->raw_pkt[1],
                            current_time.tv_sec,
                            current_time.tv_usec);
                }

                /* Since we do not have pip/ptcp pointer, we have to manually get the flow info from pkt_ptr */
                hval = pkt_desc_ptr->pkt_ptr->addr_pair.hash % GLOBALS.Hash_Table_Size;
                IP_COPYADDR(&pkt_in.a_address, pkt_desc_ptr->pkt_ptr->addr_pair.a_address);
                IP_COPYADDR(&pkt_in.b_address, pkt_desc_ptr->pkt_ptr->addr_pair.b_address);
                pkt_in.a_port = pkt_desc_ptr->pkt_ptr->addr_pair.a_port;
                pkt_in.b_port = pkt_desc_ptr->pkt_ptr->addr_pair.b_port;
                pkt_in.hash = pkt_desc_ptr->pkt_ptr->addr_pair.hash;

                /* Find entry in hash table */
                for (flow_hash_ptr = flow_hash_table[hval]; flow_hash_ptr; flow_hash_ptr = flow_hash_ptr->next)
                {
                    if (SameConn(&pkt_in, &flow_hash_ptr->addr_pair, &dir))
                    {
                        /* Found */
                        is_found = TRUE;
                        break;
                    }
                }

                if (is_found)
                {
                    if (SendPkt(pkt_desc_ptr->pkt_ptr->raw_pkt, pkt_desc_ptr->pkt_ptr->pkt_len) == -1)
                    {
                        fprintf(fp_stderr, "TIMEOUT_MGMT: Error: Cannot send the packet!\n");
                    }
                    FreePkt(pkt_desc_ptr->pkt_ptr);
                    FreeFlowHash(flow_hash_ptr);
                    // fprintf(fp_stderr, "TIMEOUT_MGMT: size: %ld!\n", circular_buf_size(circ_buf));
                }
                else
                {
                    fprintf(fp_stderr, "TIMEOUT_MGMT: Error: Cannot find the flow in the hash table!\n");
                }
            }
        }
    }
}

void trace_init(void)
{
    static Bool initted = FALSE;

    if (initted)
        return;

    initted = TRUE;

    /* initialize the mutex lock for two threads */
    pthread_mutex_init(&g_tMutex, NULL);
    pthread_cond_init(&cond, NULL);

    /* create an array to hold any pairs that we might create */
    pkt_arr = (ip_packet **)MallocZ(GLOBALS.Max_TCP_Packets * sizeof(ip_packet *));

    /* initalize the packet descriptor buffer for the circular buffer */
    pkt_desc_buf = (pkt_desc_t **)MallocZ(GLOBALS.Max_TCP_Packets * sizeof(pkt_desc_t *));

    /* initalize the circular buffer */
    circ_buf = circular_buf_init(pkt_desc_buf, GLOBALS.Max_TCP_Packets);

    /* initialize the hash table */
    flow_hash_table = (flow_hash **)MallocZ(GLOBALS.Hash_Table_Size * sizeof(flow_hash *));
}

/* Helper functions */
void print_pkt_arr()
{
    int p;

    for (p = 0; p < 20; p++)
    {
        fprintf(fp_stdout, "[%2d]", p);
        if (pkt_arr[p] != NULL)
            fprintf(fp_stdout, "->[ppkt] src_ip: %s src_port: %d \n", inet_ntoa(pkt_arr[p]->addr_pair.a_address.un.ip4), pkt_arr[p]->addr_pair.a_port);
        else
            fprintf(fp_stdout, "->[NULL]\n");
    }
}
