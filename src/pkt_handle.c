#include "tsdn.h"

/* Log  */
int search_count = 0;

int num_ip_packets = -1;    /* how many packets we've allocated */
ip_packet **pkt_arr = NULL; /* array of pointers to allocated packets */
u_long hash_table_size = HASH_TABLE_SIZE;

Bool warn_MAX_ = TRUE;

static ip_packet *
NewPkt(struct ether_header *peth, struct ip *pip, void *ptcp, void *plast, struct timeval *pckt_time)
{
    ip_packet *ppkt;
    int old_new_ip_packets = num_ip_packets;
    int steps = 0;

    /* look for the next eventually available free block */
    num_ip_packets++;
    num_ip_packets = num_ip_packets % MAX_TCP_PACKETS;

    /* make a new one, if possible */
    while ((num_ip_packets != old_new_ip_packets) && (pkt_arr[num_ip_packets] != NULL) && (steps < LIST_SEARCH_DEPT))
    {
        steps++;
        /* look for the next one */
        //         fprintf (fp_log, "%d %d\n", num_tcp_pairs, old_new_tcp_pairs);
        num_ip_packets++;
        num_ip_packets = num_ip_packets % MAX_TCP_PACKETS;
    }
    if (pkt_arr[num_ip_packets] != NULL)
    {
        if (warn_MAX_)
        {
            fprintf(fp_log, "\n"
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

static flow_hash_t *
FindFlowHash(struct ip *pip, void *ptcp, void *plast, int *pdir)
{
    flow_addrblock pkt_in;
    hash hval;
    flow_hash_t *flow_hash_ptr;

    /* grab the address from this packet */
    CopyAddr(&pkt_in, pip, ptcp);

    /* grab the hash value (already computed by CopyAddr) */
    hval = pkt_in.hash % hash_table_size;
#ifdef HASH_TABLE_LOCK
    pthread_mutex_lock(&flow_hash_mutex);
#endif
    /* Search in the linked lists with the same hash value */
    for (flow_hash_ptr = flow_hash_table[hval]; flow_hash_ptr; flow_hash_ptr = flow_hash_ptr->next)
    {
        if (SameConn(&pkt_in, &flow_hash_ptr->addr_pair, pdir))
        {
            /* Found */
            pthread_mutex_unlock(&flow_hash_mutex);
            return flow_hash_ptr;
        }
    }
#ifdef HASH_TABLE_LOCK
    pthread_mutex_unlock(&flow_hash_mutex);
#endif
    return NULL;
}

static flow_hash_t *CreateFlowHash(struct ether_header *peth, struct ip *pip, void *ptcp, void *plast, struct timeval *pckt_time, circular_buf_t *circ_buf)
{
    static ip_packet *temp_pkt;
    pkt_desc_t *temp_pkt_desc_ptr;
    pkt_desc_t **temp_pkt_desc_pp;
    flow_hash_t *temp_flow_hash_ptr;
    flow_hash_t *flow_hash_head_ptr;
    hash hval;

    /* Buffer packet */
    temp_pkt = NewPkt(peth, pip, ptcp, plast, pckt_time);
    if (temp_pkt == NULL) /* not enough memory to store the new flow */
    {
        if (debug > 0)
        {
            fprintf(fp_log,
                    "** out of memory when creating flowsp\n");
        }
        return (NULL);
    }
    /* Create packet descriptor */
    temp_pkt_desc_ptr = pkt_desc_alloc(); // all packet descriptors are allocated from the same pool (share the same free list)
    temp_pkt_desc_ptr->pkt_ptr = temp_pkt;
    temp_pkt_desc_ptr->recv_time = *pckt_time;

    /* Push into circular buffer */
    temp_pkt_desc_pp = (pkt_desc_t **)circular_buf_try_put(circ_buf, (void *)temp_pkt_desc_ptr);
    if (temp_pkt_desc_pp == NULL)
    {
        fprintf(fp_log, "Error: Circular buffer is full\n");
        return NULL;
    }
    /* Create entry for hash table */
    hval = temp_pkt->addr_pair.hash % hash_table_size;
#ifdef HASH_TABLE_LOCK
    pthread_mutex_lock(&flow_hash_mutex);
#endif
    flow_hash_head_ptr = flow_hash_table[hval];

    temp_flow_hash_ptr = flow_hash_alloc();
    temp_flow_hash_ptr->addr_pair = temp_pkt->addr_pair;
    temp_flow_hash_ptr->pkt_desc_ptr = temp_pkt_desc_ptr;
    temp_flow_hash_ptr->pkt_desc_ptr_ptr = temp_pkt_desc_pp;
    temp_flow_hash_ptr->lazy_pending = FALSE;

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

    /* Store a pointer in packet descriptor */
    temp_pkt_desc_ptr->flow_hash_ptr = temp_flow_hash_ptr;
#ifdef HASH_TABLE_LOCK
    pthread_mutex_unlock(&flow_hash_mutex);
#endif
    return temp_flow_hash_ptr;
}

void FreePkt(ip_packet *ppkt_temp)
{
    pkt_arr[ppkt_temp->loc_pkt_arr] = NULL;
    pkt_release(ppkt_temp);
}

void FreePktDesc(pkt_desc_t *pkt_desc_ptr)
{
    pkt_desc_release(pkt_desc_ptr);
}

void FreeFlowHash(flow_hash_t *flow_hash_ptr)
{

    hash hval;
    flow_hash_t *flow_hash_head_ptr;

    hval = flow_hash_ptr->addr_pair.hash % hash_table_size;
#ifdef HASH_TABLE_LOCK
    pthread_mutex_lock(&flow_hash_mutex);
#endif

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
#ifdef HASH_TABLE_LOCK
    pthread_mutex_unlock(&flow_hash_mutex);
#endif
}

int LazyFreeFlowHash(flow_hash_t *flow_hash_ptr)
{
    assert(flow_hash_ptr != NULL);
    /* Avoid Double Free */
    if (flow_hash_ptr->pkt_desc_ptr == NULL)
    {
        return -1;
    }
    else if (flow_hash_ptr->pkt_desc_ptr->pkt_ptr == NULL)
    {
        return -1;
    }

    /* Mark the lazy pending flag */
    flow_hash_ptr->lazy_pending = TRUE;

    /* The time when we receive response packet */
    timeval current_time;
    gettimeofday(&current_time, NULL);
    flow_hash_ptr->resp_time = current_time;
    flow_hash_ptr->pkt_desc_ptr->pkt_ptr = NULL;
    flow_hash_ptr->pkt_desc_ptr = NULL;
    flow_hash_ptr->pkt_desc_ptr_ptr = NULL;

    /* Put the flow hash pointer into the lazy freeing circular buffer */
    flow_hash_t **temp_flow_hash_pp;
    temp_flow_hash_pp = (flow_hash_t **)circular_buf_try_put(lazy_flow_hash_circ_buf, (void *)flow_hash_ptr);
    if (temp_flow_hash_pp == NULL)
    {
        fprintf(fp_log, "Error: Lazy freeing circular buffer is full\n");
        return -1;
    }
#ifdef DO_STATS
    lazy_flow_hash_count++;
#endif

    /* Activate the lazy freeing thread */
    pthread_cond_signal(&lazy_flow_hash_cond);
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

int pkt_handle(struct ether_header *peth, struct ip *pip, void *ptcp, void *plast, struct timeval *pckt_time)
{
    flow_hash_t *flow_hash_ptr;
    pkt_desc_t *tmp_pkt_desc_ptr;
    int dir = 0;
    void *buf_slot;

    // struct ether_addr *eth_addr;
    // fprintf(fp_log, "Ethernet Frame: %s",
    //         ether_ntoa((struct ether_addr *)peth->ether_shost));
    // fprintf(fp_log, "->%s\n",
    //         ether_ntoa((struct ether_addr *)peth->ether_dhost));

    // use two string buffer for print the IP address transformed from inet_ntop
    char ip_src_addr_print_buffer[INET_ADDRSTRLEN], ip_dst_addr_print_buffer[INET_ADDRSTRLEN];

    /* do not rely on the header, instead check if it's already in the hash table */
    flow_hash_ptr = FindFlowHash(pip, ptcp, plast, &dir);

    /* Found the flow, then check the direction of this packet */
    if (flow_hash_ptr != NULL)
    {
        if (flow_hash_ptr->lazy_pending == TRUE)
        {
#ifdef DO_STATS
            lazy_flow_hash_hit++;
#endif
            return 0;
        }

        int timeout_level = which_circular_buf(pip);
        assert(timeout_level != -1);

        /* Same direction of this packet, probably another request */
        if (dir == C2S)
        {
            return 0;
        }
        /* Reversed direction of this packet, probably a response */
        else if (dir == S2C)
        {
            /* the critical resource is the head of the circular buffer */
            // pthread_mutex_lock(&circ_buf_head_mutex_list[timeout_level]);
            if (debug > 1)
            {
                inet_ntop(AF_INET, &(flow_hash_ptr->addr_pair.a_address.un.ip4), ip_src_addr_print_buffer, INET_ADDRSTRLEN);
                inet_ntop(AF_INET, &(flow_hash_ptr->addr_pair.b_address.un.ip4), ip_dst_addr_print_buffer, INET_ADDRSTRLEN);
                fprintf(fp_log, "pkt_handle: S2C: from %s:%d to %s:%d with %d bytes of raw_packet %c%c.. at %ld\n",
                        ip_src_addr_print_buffer,
                        flow_hash_ptr->addr_pair.a_port,
                        ip_dst_addr_print_buffer,
                        flow_hash_ptr->addr_pair.b_port,
                        flow_hash_ptr->pkt_desc_ptr->pkt_ptr->pkt_len,
                        flow_hash_ptr->pkt_desc_ptr->pkt_ptr->raw_pkt[0],
                        flow_hash_ptr->pkt_desc_ptr->pkt_ptr->raw_pkt[1],
                        flow_hash_ptr->pkt_desc_ptr->recv_time.tv_sec);
            }
            ip_packet *pkt_ptr = flow_hash_ptr->pkt_desc_ptr->pkt_ptr;
            pkt_desc_t *pkt_desc_ptr = flow_hash_ptr->pkt_desc_ptr;

            /* Install Flow Entry */
            if (try_install_drop_entry(flow_hash_ptr->addr_pair.a_address.un.ip4,
                                       flow_hash_ptr->addr_pair.b_address.un.ip4,
                                       flow_hash_ptr->addr_pair.a_port,
                                       flow_hash_ptr->addr_pair.b_port,
                                       flow_hash_ptr->addr_pair.protocol))
            {
                fprintf(fp_log, "Error: Failed to install flow entry\n");
                return -1;
            }

            LazyFreeFlowHash(flow_hash_ptr);
            *(flow_hash_ptr->pkt_desc_ptr_ptr) = NULL;

#ifdef DO_STATS
            replied_flow_count_tot++;
            switch (timeout_level)
            {
            case 0:
                replied_flow_count_tcp++;
                pkt_buf_count--;
                pkt_desc_count--;
                break;
            case 1:
                replied_flow_count_udp++;

                pkt_buf_count--;
                pkt_desc_count--;
                break;
            case 2:
                replied_flow_count_icmp++;
                pkt_buf_count--;
                pkt_desc_count--;
                break;
            default:
                break;
            }
#endif
        }
    }
    /* Did not find the flow, create one */
    else
    {
        int timeout_level = which_circular_buf(pip);
        assert(timeout_level != -1);
        flow_hash_ptr = CreateFlowHash(peth, pip, ptcp, plast, pckt_time, circ_buf_list[timeout_level]);
#ifdef DO_STATS
        switch (timeout_level)
        {
        case 0:
            pkt_buf_count++;
            flow_hash_count++;
            pkt_desc_count++;
            circ_buf_L1_count++;
            break;
        case 1:
            pkt_buf_count++;
            flow_hash_count++;
            pkt_desc_count++;
            circ_buf_L2_count++;
            break;
        case 2:
            pkt_buf_count++;
            flow_hash_count++;
            pkt_desc_count++;
            circ_buf_L3_count++;
            break;
        default:
            break;
        }
#endif
        /* Calculate the packet processing time */
        // timeval current_time, pkt_time;
        // int time_diff;
        // pkt_time = flow_hash_ptr->pkt_desc_ptr->recv_time;
        // gettimeofday(&current_time, NULL);
        // time_diff = tv_sub_2(current_time, pkt_time);

        /* Weak up the timeout_mgmt thread */
        if (!circular_buf_empty(circ_buf_list[timeout_level]))
        {
            pthread_cond_signal(&(circ_buf_cond_list[timeout_level]));
        }

        // if (debug > 1)
        // {
        //     inet_ntop(AF_INET, &(flow_hash_ptr->addr_pair.a_address.un.ip4), ip_src_addr_print_buffer, INET_ADDRSTRLEN);
        //     inet_ntop(AF_INET, &(flow_hash_ptr->addr_pair.b_address.un.ip4), ip_dst_addr_print_buffer, INET_ADDRSTRLEN);
        //     fprintf(fp_log, "PKT_RX: new request pkt stored: from %s:%d to %s:%d with %d bytes of raw_packet %s at %ld.%5ld\n",
        //             ip_src_addr_print_buffer,
        //             ntohs(flow_hash_ptr->addr_pair.a_port),
        //             ip_dst_addr_print_buffer,
        //             ntohs(flow_hash_ptr->addr_pair.b_port),
        //             flow_hash_ptr->pkt_desc_ptr->pkt_ptr->pkt_len,
        //             ether_ntoa((struct ether_addr *)flow_hash_ptr->pkt_desc_ptr->pkt_ptr->raw_pkt),
        //             // inet_ntoa(*(struct in_addr *)(flow_hash_ptr->pkt_desc_ptr->pkt_ptr->raw_pkt + 26)),
        //             flow_hash_ptr->pkt_desc_ptr->recv_time.tv_sec,
        //             flow_hash_ptr->pkt_desc_ptr->recv_time.tv_usec);
        // }
    }
}

void trace_init(void)
{
    static Bool initted = FALSE;

    if (initted)
        return;

    initted = TRUE;

    /* create an array to hold any pairs that we might create */
    pkt_arr = (ip_packet **)MallocZ(MAX_TCP_PACKETS * sizeof(ip_packet *));

    for (int i = 0; i < TIMEOUT_LEVEL_NUM; i++)
    {
        /* initialize the mutex lock for two threads */
        pthread_mutex_init(&circ_buf_mutex_list[i], NULL);
        pthread_cond_init(&circ_buf_cond_list[i], NULL);

        pthread_mutex_init(&circ_buf_head_mutex_list[i], NULL);

        /* initalize the packet descriptor buffer for the circular buffer */
        pkt_desc_buf_list[i] = (pkt_desc_t **)MallocZ(MAX_TCP_PACKETS * sizeof(pkt_desc_t *));

        /* initalize the circular buffer */
        circ_buf_list[i] = circular_buf_init((void **)pkt_desc_buf_list[i], MAX_TCP_PACKETS);
    }

    /* initialize the hash table */
    flow_hash_table = (flow_hash_t **)MallocZ(hash_table_size * sizeof(flow_hash_t *));
    #ifdef HASH_TABLE_LOCK
    pthread_mutex_init(&flow_hash_mutex, NULL);
    #endif

    /* initialize the circular buffer for lazy freeing */
    lazy_flow_hash_buf = (flow_hash_t **)MallocZ(MAX_TCP_PACKETS * sizeof(flow_hash_t *));
    lazy_flow_hash_circ_buf = circular_buf_init((void **)lazy_flow_hash_buf, MAX_TCP_PACKETS);

    /* initialize the mutex lock for lazy freeing */
    pthread_mutex_init(&lazy_flow_hash_mutex, NULL);
    pthread_cond_init(&lazy_flow_hash_cond, NULL);

    /* Initialize the params for sendpkt */
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

/* Helper functions */
void print_pkt_arr()
{
    int p;

    for (p = 0; p < 20; p++)
    {
        fprintf(fp_log, "[%2d]", p);
        if (pkt_arr[p] != NULL)
            fprintf(fp_log, "->[ppkt] src_ip: %s src_port: %d \n", inet_ntoa(pkt_arr[p]->addr_pair.a_address.un.ip4), pkt_arr[p]->addr_pair.a_port);
        else
            fprintf(fp_log, "->[NULL]\n");
    }
}
