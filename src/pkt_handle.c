#include "tsdn.h"

int num_ip_packets = -1;           /* how many packets we've allocated */
static ip_packet **pkt_arr = NULL; /* array of pointers to allocated packets */
static pkt_desc_t **pkt_desc_arr = NULL;
int pkt_index = 0;
int entry_index = 0;
// static timeval current_pkt_time;

/* Circular Buffer for pkt buffer */
static circular_buf_t *pkt_circ_buf;

char ip_src_addr_print_buffer[INET_ADDRSTRLEN];
char ip_dst_addr_print_buffer[INET_ADDRSTRLEN];

void print_pkt_arr()
{
    for (int i = 0; i < PKT_BUF_SIZE; i++)
    {
        if (pkt_arr[i] != NULL)
        {
            printf("pkt_arr[%d] is not NULL at memory %p, ", i, &pkt_arr[i]);
            printf("loc_pkt_arr = %d, ", pkt_arr[i]->loc_pkt_arr);
        }
    }
}

static pkt_desc_t *NewPkt(struct ether_header *peth, struct ip *pip, void *ptcp, void *plast)
{
    ip_packet *ppkt;
    pkt_desc_t *ppkt_desc;
    int old_new_ip_packets = num_ip_packets;
    int steps = 0;

    /* look for the next eventually available free block */
    num_ip_packets = (num_ip_packets + 1) % PKT_BUF_SIZE;

    /* make a new one, if possible */
    while ((num_ip_packets != old_new_ip_packets) && (pkt_arr[num_ip_packets] != NULL) && (steps < LIST_SEARCH_DEPT))
    {
        steps++;
        /* look for the next one */
        num_ip_packets++;
        num_ip_packets = num_ip_packets % PKT_BUF_SIZE;
    }
    assert(pkt_arr[num_ip_packets] == NULL);

    /* create a new packet buffer */
    ppkt = pkt_arr[num_ip_packets] = pkt_alloc();
    ppkt->loc_pkt_arr = num_ip_packets;

    /* create a new packet descriptor */
    ppkt_desc = pkt_desc_alloc();
    /* grab the address from this packet */
    CopyAddr(&ppkt_desc->addr_pair, pip, ptcp);
    ppkt_desc->ppkt = ppkt;
    ppkt_desc->is_replied = FALSE;
    /* Not used for now */
    ppkt_desc->internal_src = internal_src;
    ppkt_desc->internal_dst = internal_dst;

    ppkt_desc->pkt_len = ntohs(pip->ip_len) + ETHER_HDR_LEN;
    if (ppkt_desc->pkt_len > SNAP_LEN)
    {
        ppkt_desc->pkt_len = SNAP_LEN;
    }
    /* Copy raw bytes */
    memcpy(ppkt->raw_pkt, peth, ppkt_desc->pkt_len);

    ppkt_desc->recv_time = current_time;

    /* push pkt_desc to circular buf */
    pkt_desc_t **tmp_pkt_desc_pp = (pkt_desc_t **)circular_buf_try_put(pkt_circ_buf, (void *)ppkt_desc);
    assert(tmp_pkt_desc_pp != NULL);

    return ppkt_desc;
}

#ifdef FLOW_HASH_MEASURE
static inline void FlowHashRecordLookup(int search_depth)
{
    flow_hash_total_lookups++;
    flow_hash_total_probes += (uint64_t)search_depth;

    if (search_depth > flow_hash_max_depth)
        flow_hash_max_depth = search_depth;

    if (search_depth <= FLOW_HASH_MAX_DEPTH)
        flow_hash_depth_hist[search_depth]++;
    else
        flow_hash_depth_hist[FLOW_HASH_MAX_DEPTH]++;

    if (search_depth > 1)
        flow_hash_collision_lookups++;
}
#endif

static flow_hash_t *FindFlowHash(struct ip *pip, void *ptcp, void *plast, int *pdir)
{
    /* Start to check */
    flow_addrblock pkt_in;
    flow_hash_t *flow_hash_ptr;

    /* grab the address from this packet */
    CopyAddr(&pkt_in, pip, ptcp);

    /* grab the hash value (already computed by CopyAddr) */
    uint32_t hash_index = pkt_in.hash_index;
    uint32_t search_depth = 0;

    /* Search in the linked lists with the same hash value */
    for (flow_hash_ptr = flow_hash_table[hash_index]; flow_hash_ptr; flow_hash_ptr = flow_hash_ptr->next)
    {
        search_depth++;
        if (SameConn(&pkt_in, &flow_hash_ptr->addr_pair, pdir))
        {
// Found
#ifdef FLOW_HASH_MEASURE
            FlowHashRecordLookup(search_depth);
#endif
            return flow_hash_ptr;
        }
    }

// Not found
#ifdef FLOW_HASH_MEASURE
    FlowHashRecordLookup(search_depth);
    flow_hash_missed_lookups++;
#endif
    return NULL;
}

void check_timeout_lazy()
{
    int ix = 0;
    flow_hash_t *flow_hash_head_ptr, *flow_hash_ptr;
    flow_hash_t *to_clean[FLOW_HASH_TABLE_GC_SIZE * 4];
    int clean_idx = 0;

    // 第一阶段：标记要清理的 flow（避免在遍历中破坏链表）
    for (ix = entry_index; ix < entry_index + FLOW_HASH_TABLE_GC_SIZE; ix++)
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
                if (tv_sub_2(current_time, flow_hash_ptr->last_pkt_time) >= FLOW_HASH_TABLE_GC_TIMEOUT)
                {
                    to_clean[clean_idx++] = flow_hash_ptr;
                }
            }
        }
    }

    // 第二阶段：真正清理 flow
    for (int i = 0; i < clean_idx; ++i)
    {
        FreeFlowHash(to_clean[i]);
#ifdef DO_STATS
        lazy_flow_hash_count--;
#endif
    }

    entry_index = (entry_index + FLOW_HASH_TABLE_GC_SIZE) % FLOW_HASH_TABLE_SIZE;
}

void check_timeout_periodic()
{
    int ix, ret;
    pkt_desc_t *tmp_ppkt_desc;
    int elapsed_time, ip_p;

    for (ix = 0; ix < PKT_BUF_GC_SPLIT_SIZE; ix++)
    {
        ret = circular_buf_peek_head(pkt_circ_buf, (void **)&tmp_ppkt_desc);
        if (ret == -1)
        {
            // buffer is empty
            break;
        }
        // printf("Check pkt (%s:%d -> %s:%d, protocol: %d, replied %d)\n",
        //        inet_ntop(AF_INET, &tmp_ppkt->addr_pair.a_address.un.ip4, ip_src_addr_print_buffer, INET_ADDRSTRLEN),
        //        ntohs(tmp_ppkt->addr_pair.a_port),
        //        inet_ntop(AF_INET, &tmp_ppkt->addr_pair.b_address.un.ip4, ip_dst_addr_print_buffer, INET_ADDRSTRLEN),
        //        ntohs(tmp_ppkt->addr_pair.b_port),
        //        tmp_ppkt->addr_pair.protocol,
        //        tmp_ppkt->is_replied);

        // Check if the packet is replied
        if (tmp_ppkt_desc->is_replied)
        {
            ret = circular_buf_get(pkt_circ_buf, (void **)&tmp_ppkt_desc);
            assert(ret == 0);
        }
        else
        {
            elapsed_time = tv_sub_2(current_time, tmp_ppkt_desc->recv_time);
            if (elapsed_time >= PKT_TIMEOUT)
            {
                ret = circular_buf_get(pkt_circ_buf, (void **)&tmp_ppkt_desc);
                assert(ret == 0);

                if (SendPkt(tmp_ppkt_desc->ppkt->raw_pkt, tmp_ppkt_desc->pkt_len) == -1)
                {
                    send_pkt_error_count++;
                }

                ip_p = tmp_ppkt_desc->addr_pair.protocol;
                FreeFlowHash(tmp_ppkt_desc->flow_hash_ptr);
                FreePkt(tmp_ppkt_desc->ppkt);
#ifdef DO_STATS
                expired_pkt_count_tot++;
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
// #ifdef LOG_TO_FILE
//                 if (expired_pkt_count_tot % PKT_LOG_SAMPLE_CNT == 0)
//                 {
//                     log_stats("timeout,%d", elapsed_time);
//                 }
// #endif
#endif
            }
            else
            {
                break;
            }
        }
    }
}

static flow_hash_t *CreateFlowHash(struct ether_header *peth, struct ip *pip, void *ptcp, void *plast)
{
    static pkt_desc_t *ppkt_desc;
    flow_hash_t *temp_flow_hash_ptr;
    flow_hash_t *flow_hash_head_ptr;

    /* Buffer packet */
    ppkt_desc = NewPkt(peth, pip, ptcp, plast);
    assert(ppkt_desc != NULL);

    /* Create entry for hash table */
    uint32_t hash_index = ppkt_desc->addr_pair.hash_index;
    flow_hash_head_ptr = flow_hash_table[hash_index];

    temp_flow_hash_ptr = flow_hash_alloc();
    temp_flow_hash_ptr->addr_pair = ppkt_desc->addr_pair;
    temp_flow_hash_ptr->lazy_pending = FALSE;
    temp_flow_hash_ptr->pkt_desc_ptr = ppkt_desc;

    if (flow_hash_head_ptr == NULL)
    {
        /* it is the first entry in the slot */
        temp_flow_hash_ptr->prev = NULL;
        temp_flow_hash_ptr->next = flow_hash_head_ptr;
        flow_hash_table[hash_index] = temp_flow_hash_ptr;
    }
    else
    {
        /* it is not the first entry in the slot, insert it to the head  */
        flow_hash_head_ptr->prev = temp_flow_hash_ptr;
        temp_flow_hash_ptr->prev = NULL;
        temp_flow_hash_ptr->next = flow_hash_head_ptr;
        flow_hash_table[hash_index] = temp_flow_hash_ptr;
    }
    ppkt_desc->flow_hash_ptr = temp_flow_hash_ptr;

    return temp_flow_hash_ptr;
}

void FreePkt(ip_packet *ppkt_temp)
{
    pkt_arr[ppkt_temp->loc_pkt_arr] = NULL;
    pkt_release(ppkt_temp);
#ifdef DO_STATS
    pkt_buf_count--;
#endif
}

void FreePktDesc(pkt_desc_t *ppkt_desc)
{
    pkt_desc_release(ppkt_desc);
}

void FreeFlowHash(flow_hash_t *flow_hash_ptr)
{
    assert(flow_hash_ptr != NULL);

    flow_hash_t *prev = flow_hash_ptr->prev;
    flow_hash_t *next = flow_hash_ptr->next;

    uint32_t hash_index = flow_hash_ptr->addr_pair.hash_index;

    assert(flow_hash_table[hash_index] != NULL);
    if (flow_hash_table[hash_index] == flow_hash_ptr)
    {
        flow_hash_table[hash_index] = next;
    }
    if (prev != NULL)
    {
        prev->next = next;
    }
    if (next != NULL)
    {
        next->prev = prev;
    }
    flow_hash_release(flow_hash_ptr);

#ifdef DO_STATS
    flow_hash_count--;
#endif
}

int LazyFreeFlowHash(flow_hash_t *flow_hash_ptr)
{
    assert(flow_hash_ptr != NULL);
    /* Mark the lazy pending flag */
    flow_hash_ptr->lazy_pending = TRUE;
    /* The time when we receive response packet */
    flow_hash_ptr->last_pkt_time = current_time;

#ifdef DO_STATS
    lazy_flow_hash_count++;
#endif
    return 0;
}

/* Main entry of packet handler */
int pkt_handle(struct ether_header *peth, struct ip *pip, void *ptcp, void *plast)
{

    /* Garbage Collection */
    if (elapsed(last_pkt_cleaned_time, current_time) > PKT_BUF_GC_PERIOD)
    {
        /* Do the expired packet checking */
        last_pkt_cleaned_time = current_time;
        check_timeout_periodic();
    }

    /* Lazy Free */
    if (elapsed(last_hash_cleaned_time, current_time) > FLOW_HASH_TABLE_GC_PERIOD)
    {
        /* Do the lazy freeing */
        last_hash_cleaned_time = current_time;
        check_timeout_lazy();
    }

    // gettimeofday(&current_pkt_time, NULL);
    flow_hash_t *flow_hash_ptr;
    int dir = 0;

    /* do not rely on the header, instead check if it's already in the hash table */
    flow_hash_ptr = FindFlowHash(pip, ptcp, plast, &dir);

    /* Found the flow, then check the direction of this packet */
    if (flow_hash_ptr != NULL)
    {
        if (flow_hash_ptr->lazy_pending == TRUE)
        {
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
            FreePkt(flow_hash_ptr->pkt_desc_ptr->ppkt);
            flow_hash_ptr->pkt_desc_ptr->is_replied = TRUE;
            flow_hash_ptr->pkt_desc_ptr->ppkt = NULL;
            /* Install Flow Entry */
            // printf("installing flow entry, src: %s:%d -> ",
            //        inet_ntop(AF_INET, &flow_hash_ptr->addr_pair.a_address.un.ip4, ip_src_addr_print_buffer, INET_ADDRSTRLEN),
            //        ntohs(flow_hash_ptr->addr_pair.a_port));
            // printf("dst: %s:%d, protocol: %d\n",
            //          inet_ntop(AF_INET, &flow_hash_ptr->addr_pair.b_address.un.ip4, ip_dst_addr_print_buffer, INET_ADDRSTRLEN),
            //          ntohs(flow_hash_ptr->addr_pair.b_port),
            //          flow_hash_ptr->addr_pair.protocol);

            if (internal_ip(flow_hash_ptr->addr_pair.a_address.un.ip4))
            {
                int ret = p4_batch_add_rule(flow_hash_ptr->addr_pair.a_address.un.ip4,
                                            flow_hash_ptr->addr_pair.a_port,
                                            flow_hash_ptr->addr_pair.protocol);

                if (ret == 0)
                {
                    // ok
                }
                else if (ret == 1 || ret == -1)
                {
                    entry_install_error_count++;
                }
                else if (ret == 2)
                {
                    entry_install_dedup_count++;
                }
            }
            else if (internal_ip(flow_hash_ptr->addr_pair.b_address.un.ip4))
            {
                int ret = p4_batch_add_rule(flow_hash_ptr->addr_pair.b_address.un.ip4,
                                            flow_hash_ptr->addr_pair.b_port,
                                            flow_hash_ptr->addr_pair.protocol);
                if (ret == 0)
                {
                    // ok
                }
                else if (ret == 1 || ret == -1)
                {
                    entry_install_error_count++;
                }
                else if (ret == 2)
                {
                    entry_install_dedup_count++;
                }
            }
            else
            {
                printf("Error: Non of the src nor dst IP is internal!\n");
                return -1;
            }
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
    pkt_desc_arr = (pkt_desc_t **)MallocZ(PKT_BUF_SIZE * sizeof(pkt_desc_t *));

    pkt_circ_buf = circular_buf_init((void **)pkt_desc_arr, PKT_BUF_SIZE);

    /* initialize the hash table */
    flow_hash_table = (flow_hash_t **)MallocZ(FLOW_HASH_TABLE_SIZE * sizeof(flow_hash_t *));

    /* Get interface name */
    strcpy(ifName, SEND_INTF);
    /* Open RAW socket to send on */
    if ((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1)
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
    socket_address.sll_family = AF_PACKET;
    /* Index of the network device */
    socket_address.sll_ifindex = if_idx.ifr_ifindex;
    /* Address length*/
    socket_address.sll_halen = ETH_ALEN;
    /* Destination MAC */
    // socket_address.sll_addr[0] = MY_DEST_MAC0;

#ifdef HOST_LIVENESS_MONITOR
    pthread_mutex_init(&active_internal_host_entry_mutex, NULL);
    memset(active_internal_host_send, 0, sizeof(active_internal_host_send));
    memset(active_internal_host_entry, 0, sizeof(active_internal_host_entry));
    memset(active_internal_host, 0, sizeof(active_internal_host));
#endif

    p4_batch_init("/tmp/p4_controller.sock");
}

void trace_check(void)
{
    assert(pkt_arr != NULL);
    assert(pkt_desc_arr != NULL);
    assert(flow_hash_table != NULL);
    assert(pkt_circ_buf != NULL);
    assert(circular_buf_size(pkt_circ_buf) == 0);
}

void trace_cleanup()
{
    /* free the flow hash table */
    for (int i = 0; i < FLOW_HASH_TABLE_SIZE; i++)
    {
        flow_hash_t *flow_hash_ptr = flow_hash_table[i];
        while (flow_hash_ptr != NULL)
        {
            flow_hash_t *temp = flow_hash_ptr;
            flow_hash_ptr = flow_hash_ptr->next;
            free(temp);
        }
    }
    free(flow_hash_table);

    /* free the pkt descriptor buffer */
    for (int i = 0; i < PKT_BUF_SIZE; i++)
    {
        if (pkt_desc_arr[i] != NULL)
        {
            free(pkt_desc_arr[i]);
        }
    }
    free(pkt_desc_arr);

    /* free the packet buffer */
    for (int i = 0; i < PKT_BUF_SIZE; i++)
    {
        if (pkt_arr[i] != NULL)
        {
            free(pkt_arr[i]);
        }
    }
    free(pkt_arr);
}
