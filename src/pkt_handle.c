#include "tsdn.h"

/* Log  */
int search_count = 0;

int num_ip_packets = -1;           /* how many packets we've allocated */
static ip_packet **pkt_arr = NULL; /* array of pointers to allocated packets */
int pkt_index = 0;
int entry_index = 0;

/* Circular Buffer for lazy freeing */
// static circular_buf_t *lazy_hash_buf;

char ip_src_addr_print_buffer[INET_ADDRSTRLEN];
char ip_dst_addr_print_buffer[INET_ADDRSTRLEN];

static ip_packet *
NewPkt(struct ether_header *peth, struct ip *pip, void *ptcp, void *plast)
{
    ip_packet *ppkt;
    int old_new_ip_packets = num_ip_packets;
    int steps = 0;

    /* look for the next eventually available free block */
    num_ip_packets = (num_ip_packets + 1) % PKT_BUF_SIZE;

    /* make a new one, if possible */
    while ((num_ip_packets != old_new_ip_packets) && (pkt_arr[num_ip_packets] != NULL) && (steps < LIST_SEARCH_DEPT))
    {
        steps++;
        /* look for the next one */
        //         fprintf (fp_log, "%d %d\n", num_tcp_pairs, old_new_tcp_pairs);
        num_ip_packets++;
        num_ip_packets = num_ip_packets % PKT_BUF_SIZE;
    }
    assert(pkt_arr[num_ip_packets] == NULL);

    /* create a new TCP pair record and remember where you put it */
    ppkt = pkt_arr[num_ip_packets] = pkt_alloc();

    /* grab the address from this packet */
    CopyAddr(&ppkt->addr_pair, pip, ptcp);

    ppkt->internal_src = internal_src;
    ppkt->internal_dst = internal_dst;

    /* Here we store raw packets starting from Ether header */
    ppkt->pkt_len = ntohs(pip->ip_len) + ETHER_HDR_LEN;
    if (ppkt->pkt_len > MAX_PKT_MTU)
    {
        ppkt->pkt_len = MAX_PKT_MTU;
    }

    memcpy(ppkt->raw_pkt, peth, ppkt->pkt_len);
    ppkt->loc_pkt_arr = num_ip_packets;
    return pkt_arr[num_ip_packets];
}

static flow_hash_t *
FindFlowHash(struct ip *pip, void *ptcp, void *plast, int *pdir)
{
    flow_addrblock pkt_in;
    hash hval;
    flow_hash_t *flow_hash_ptr;

    /* grab the address from this packet */
    CopyAddr(&pkt_in, pip, ptcp);

    /* grab the hash value (already computed by CopyAddr) */
    hval = pkt_in.hash % HASH_TABLE_SIZE;
    /* Search in the linked lists with the same hash value */
    for (flow_hash_ptr = flow_hash_table[hval]; flow_hash_ptr; flow_hash_ptr = flow_hash_ptr->next)
    {
        if (SameConn(&pkt_in, &flow_hash_ptr->addr_pair, pdir))
        {
            /* Found */
            return flow_hash_ptr;
        }
    }

    /* Garbage Collection */
    if (elapsed(last_pkt_cleaned_time, current_time) > GARBAGE_PERIOD)
    {
        /* Do the expired packet checking */
        last_pkt_cleaned_time = current_time;
        check_timeout_periodic();
    }

    /* Lazy Free */
    if (elapsed(last_hash_cleaned_time, current_time) > LAZY_FREEING_PERIOD)
    {
        /* Do the lazy freeing */
        last_hash_cleaned_time = current_time;
        check_timeout_lazy();
    }

    return NULL;
}

void check_timeout_lazy()
{
    int ix, tot_pkt = 0;

    flow_hash_t *flow_hash_head_ptr, *flow_hash_ptr;

    for (ix = entry_index; ix < entry_index + LAZY_FREEING_RATIO; ix++)
    {
        flow_hash_head_ptr = flow_hash_table[ix];
        if (flow_hash_head_ptr == NULL)
        {
            continue;
        }

        for (flow_hash_ptr = flow_hash_head_ptr; flow_hash_ptr; flow_hash_ptr = flow_hash_ptr->next)
        {
            if (flow_hash_ptr->lazy_pending == TRUE)
            {
                if (tv_sub_2(current_time, flow_hash_ptr->last_pkt_time) >= LAZY_FREEING_TIMEOUT)
                {
                    FreeFlowHash(flow_hash_ptr);
#ifdef DO_STATS
                    lazy_flow_hash_count--;
                    lazy_flow_hash_hit++;
                    flow_hash_count--;
#endif
                }
            }
        }
    }
    entry_index = (entry_index + LAZY_FREEING_RATIO) % HASH_TABLE_SIZE;
}

void check_timeout_periodic()
{
    int ix, idx;
    int elapsed_time = 0;
    int ip_p;

    ip_packet *ppkt;
    for (ix = pkt_index; ix < pkt_index + GARBAGE_SPLIT_RATIO; ix++)
    {
        idx = ix % PKT_BUF_SIZE;
        ppkt = pkt_arr[idx];
        if (ppkt == NULL)
        {
            continue;
        }

        elapsed_time = tv_sub_2(current_time, ppkt->flow_hash_ptr->recv_time);

        if (elapsed_time >= TIMEOUT_LEVEL_1)
        {
            if (SendPkt(ppkt->raw_pkt, ppkt->pkt_len) == -1)
            {
                send_pkt_error_count++;
            }
            ip_p = ppkt->addr_pair.protocol;
            fprintf(fp_log, "timeout,%s,%d,%s,%d,%d\n",
                    inet_ntop(AF_INET, &ppkt->addr_pair.a_address.un.ip4, ip_src_addr_print_buffer, INET_ADDRSTRLEN),
                    ntohs(ppkt->addr_pair.a_port),
                    inet_ntop(AF_INET, &ppkt->addr_pair.b_address.un.ip4, ip_dst_addr_print_buffer, INET_ADDRSTRLEN),
                    ntohs(ppkt->addr_pair.b_port),
                    ip_p);

            FreeFlowHash(ppkt->flow_hash_ptr);
            FreePkt(ppkt);
#ifdef DO_STATS
            expired_pkt_count_tot++;
            pkt_buf_count--;
            flow_hash_count--;
            switch (ip_p)
            {
            case IPPROTO_TCP:
                expired_pkt_count_tcp++;
                break;
            case IPPROTO_UDP:
                expired_pkt_count_udp++;
                break;
            case IPPROTO_ICMP:
                expired_pkt_count_icmp++;
                break;

            default:
                break;
            }

            if (expired_pkt_count_tot % PKT_LOG_SAMPLE_CNT == 0)
            {
                log_stats("timeout,%d", elapsed_time);
            }
#endif
            pkt_arr[idx] = NULL;
        }
    }

    /* Increasing starting index for the next function call */
    pkt_index = (pkt_index + GARBAGE_SPLIT_RATIO) % PKT_BUF_SIZE;
}

static flow_hash_t *CreateFlowHash(struct ether_header *peth, struct ip *pip, void *ptcp, void *plast)
{
    static ip_packet *temp_ppkt;
    flow_hash_t *temp_flow_hash_ptr;
    flow_hash_t *flow_hash_head_ptr;
    hash hval;

    /* Buffer packet */
    temp_ppkt = NewPkt(peth, pip, ptcp, plast);
    assert(temp_ppkt != NULL);

    /* Create entry for hash table */
    hval = temp_ppkt->addr_pair.hash % HASH_TABLE_SIZE;
    flow_hash_head_ptr = flow_hash_table[hval];

    temp_flow_hash_ptr = flow_hash_alloc();
    temp_flow_hash_ptr->addr_pair = temp_ppkt->addr_pair;
    temp_flow_hash_ptr->lazy_pending = FALSE;
    temp_flow_hash_ptr->recv_time = current_time;
    temp_flow_hash_ptr->ppkt = temp_ppkt;

    if (flow_hash_head_ptr == NULL)
    {
        /* it is the first entry in the slot */
        temp_flow_hash_ptr->prev = NULL;
        temp_flow_hash_ptr->next = flow_hash_head_ptr;
        flow_hash_table[hval] = temp_flow_hash_ptr;
    }
    else
    {
        /* it is not the first entry in the slot, insert it to the head  */
        flow_hash_head_ptr->prev = temp_flow_hash_ptr;
        temp_flow_hash_ptr->prev = NULL;
        temp_flow_hash_ptr->next = flow_hash_head_ptr;
        flow_hash_table[hval] = temp_flow_hash_ptr;
    }
    temp_ppkt->flow_hash_ptr = temp_flow_hash_ptr;

    return temp_flow_hash_ptr;
}

void FreePkt(ip_packet *ppkt_temp)
{
    pkt_arr[ppkt_temp->loc_pkt_arr] = NULL;
    pkt_release(ppkt_temp);
}

void FreeFlowHash(flow_hash_t *flow_hash_ptr)
{
    hash hval;
    flow_hash_t *flow_hash_head_ptr;

    hval = flow_hash_ptr->addr_pair.hash % HASH_TABLE_SIZE;

    assert(flow_hash_table[hval] != NULL);

    flow_hash_head_ptr = flow_hash_table[hval];
    if (flow_hash_ptr == flow_hash_table[hval])
    {
        /* it is the top of the linked list */
        flow_hash_table[hval] = flow_hash_ptr->next;
        flow_hash_release(flow_hash_ptr);
    }
    else
    {
        /* it is the middle of the linked list */
        flow_hash_ptr->prev->next = flow_hash_ptr->next;
        if (flow_hash_ptr->next != NULL)
        {
            flow_hash_ptr->next->prev = flow_hash_ptr->prev;
        }
        flow_hash_release(flow_hash_ptr);
    }
}

int LazyFreeFlowHash(flow_hash_t *flow_hash_ptr)
{
    assert(flow_hash_ptr != NULL);
    /* Mark the lazy pending flag */
    flow_hash_ptr->lazy_pending = TRUE;
    /* The time when we receive response packet */
    flow_hash_ptr->last_pkt_time = current_time;
    FreePkt(flow_hash_ptr->ppkt);
#ifdef DO_STATS
    lazy_flow_hash_count++;
    pkt_buf_count--;
#endif
    return 0;
}

int which_circular_buf(struct ip *pip)
{
    switch (pip->ip_p)
    {
    case IPPROTO_TCP:
    {
        return 0;
    }
    case IPPROTO_UDP:
    {
        return 1;
    }
    case IPPROTO_ICMP:
    {
        return 2;
    }
    }
    return -1;
}

/* Main entry of packet handler */
int pkt_handle(struct ether_header *peth, struct ip *pip, void *ptcp, void *plast)
{
    flow_hash_t *flow_hash_ptr;
    int dir = 0;
    int timeout_level = which_circular_buf(pip);

    // use two string buffer for print the IP address transformed from inet_ntop
    char ip_src_addr_print_buffer[INET_ADDRSTRLEN], ip_dst_addr_print_buffer[INET_ADDRSTRLEN];

    /* do not rely on the header, instead check if it's already in the hash table */
    flow_hash_ptr = FindFlowHash(pip, ptcp, plast, &dir);

    /* Found the flow, then check the direction of this packet */
    if (flow_hash_ptr != NULL)
    {
        if (flow_hash_ptr->lazy_pending == TRUE)
        {
            // fprintf(fp_log, "Lazy Free Flow Hash Hit! (%s:%d -> %s:%d, protocol: %d)\n",
            //         inet_ntop(AF_INET, &flow_hash_ptr->addr_pair.a_address.un.ip4, ip_src_addr_print_buffer, INET_ADDRSTRLEN),
            //         ntohs(flow_hash_ptr->addr_pair.a_port),
            //         inet_ntop(AF_INET, &flow_hash_ptr->addr_pair.b_address.un.ip4, ip_dst_addr_print_buffer, INET_ADDRSTRLEN),
            //         ntohs(flow_hash_ptr->addr_pair.b_port),
            //         flow_hash_ptr->addr_pair.protocol);
#ifdef DO_STATS
            lazy_flow_hash_hit++;
#endif
            flow_hash_ptr->last_pkt_time = current_time;
            return 0;
        }

        /* Same direction of this packet, probably another request */
        if (dir == C2S)
        {
            return 0;
        }
        /* Reversed direction of this packet, probably a response */
        else if (dir == S2C)
        {
            LazyFreeFlowHash(flow_hash_ptr);
#ifdef SWITCH_ENABLED
            /* Install Flow Entry */
            if (internal_ip(flow_hash_ptr->addr_pair.a_address.un.ip4))
            {
                if (try_install_p4_entry(flow_hash_ptr->addr_pair.a_address.un.ip4,
                                         flow_hash_ptr->addr_pair.a_port,
                                         flow_hash_ptr->addr_pair.protocol))
                {
                    printf("Error: Failed to install flow entry!");
                    return -1;
                }
            }
            else if (internal_ip(flow_hash_ptr->addr_pair.b_address.un.ip4))
            {
                if (try_install_p4_entry(flow_hash_ptr->addr_pair.b_address.un.ip4,
                                         flow_hash_ptr->addr_pair.b_port,
                                         flow_hash_ptr->addr_pair.protocol))
                {
                    printf("Error: Failed to install flow entry!");
                    return -1;
                }
            }
            else
            {
                printf("Error: Non of the src nor dst IP is internal!\n");
                return -1;
            }

#ifdef DO_STATS
            replied_flow_count_tot++;
            switch (timeout_level)
            {
            case 0:
                replied_flow_count_tcp++;
                break;
            case 1:
                replied_flow_count_udp++;
                break;
            case 2:
                replied_flow_count_icmp++;
                break;
            default:
                break;
            }
#endif
#endif
            return 0;
        }
    }
    /* Did not find the flow, create one */
    else
    {
        flow_hash_ptr = CreateFlowHash(peth, pip, ptcp, plast);

#ifdef DO_STATS
        pkt_buf_count++;
        flow_hash_count++;
#endif
    }
}

void trace_init(void)
{
    static Bool initted = FALSE;

    if (initted)
        return;

    initted = TRUE;

    /* create an array to hold any pairs that we might create */
    pkt_arr = (ip_packet **)MallocZ(PKT_BUF_SIZE * sizeof(ip_packet *));

    /* initialize the hash table */
    flow_hash_table = (flow_hash_t **)MallocZ(HASH_TABLE_SIZE * sizeof(flow_hash_t *));

    /* Initialize the params for sendpkt */
    memset(&sendbuf_padding, 0, MAX_IP_PKT_LENGTH);

    /* Get interface name */
    strcpy(ifName, SEND_INTF);
    /* Open RAW socket to send on */
    if ((sockfd = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW)) == -1)
    {
        perror("socket");
    }
    /* Get the index of the interface to send on */
    memset(&if_idx, 0, sizeof(struct ifreq));
    strncpy(if_idx.ifr_name, ifName, IFNAMSIZ - 1);
    if (ioctl(sockfd, SIOCGIFINDEX, &if_idx) < 0)
        perror("SIOCGIFINDEX");
    /* Get the MAC address of the interface to send on */
    // memset(&if_mac, 0, sizeof(struct ifreq));
    // strncpy(if_mac.ifr_name, ifName, IFNAMSIZ-1);
    // if (ioctl(sockfd, SIOCGIFHWADDR, &if_mac) < 0)
    //     perror("SIOCGIFHWADDR");
    /* Construct the Ethernet header, here we use raw packet */
    // memset(sendbuf, 0, BUF_SIZ);
    /* Ethernet header */
    // eh->ether_shost[0] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[0];
    // /* Ethertype field */
    // eh->ether_type = htons(ETH_P_IP);
    // tx_len += sizeof(struct ether_header);
    // /* Fill packet data */
    // sendbuf[tx_len++] = 0xde;
    /* Index of the network device */
    socket_address.sll_ifindex = if_idx.ifr_ifindex;
    /* Address length*/
    socket_address.sll_halen = ETH_ALEN;
    /* Destination MAC */
    // socket_address.sll_addr[0] = MY_DEST_MAC0;
}

void trace_cleanup()
{
    /* free the flow hash table */
    // printf("Freeing flow hash table\n");
    // for (int i = 0; i < HASH_TABLE_SIZE; i++)
    // {
    //     flow_hash_t *flow_hash_ptr = flow_hash_table[i];
    //     while (flow_hash_ptr != NULL)
    //     {
    //         flow_hash_t *temp = flow_hash_ptr;
    //         flow_hash_ptr = flow_hash_ptr->next;
    //         free(temp);
    //     }
    // }
    // free(flow_hash_table);

    // printf("Freeing packet buffer\n");
    // /* free the packet buffer */
    // for (int i = 0; i < PKT_BUF_SIZE; i++)
    // {
    //     if (pkt_arr[i] != NULL)
    //     {
    //         free(pkt_arr[i]);
    //     }
    // }
    // free(pkt_arr);
}