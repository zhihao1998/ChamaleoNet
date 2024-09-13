#include "tsdn.h"
static timeval start_time;
static timeval end_time;

/* timeout_mgmt thread */
void *timeout_mgmt(void *args)
{
    timeout_mgmt_args *timeout_mgmt_args_ptr = (timeout_mgmt_args *)args;
    int thread_timeout = timeout_mgmt_args_ptr->timeout;
    circular_buf_t *thread_circ_buf = timeout_mgmt_args_ptr->circ_buf;
    pthread_mutex_t *thread_g_tMutex_ptr = timeout_mgmt_args_ptr->g_tMutex_ptr;
    pthread_cond_t *thread_cond_ptr = timeout_mgmt_args_ptr->cond_ptr;
    pthread_mutex_t *thread_head_mutex_ptr = timeout_mgmt_args_ptr->head_mutex_ptr;

    u_long *thread_circ_buf_count = timeout_mgmt_args_ptr->circ_buf_count;

    while (circular_buf_empty(thread_circ_buf))
    {
        fprintf(fp_log, "TIMEOUT_MGMT: Circular Buffer empty, thread blocked!\n");
        pthread_cond_wait(thread_cond_ptr, thread_g_tMutex_ptr);
    }
    pkt_desc_t *pkt_desc_ptr;
    void *buf_slot;
    hash hval;
    flow_hash_t *flow_hash_ptr;
    int dir;
    timeval current_time, pkt_time;
    int sleep_time_us, time_diff;
    int res;
    ushort ip_protocol;

    while (1)
    {
        // fprintf(fp_log, "TIMEOUT_MGMT: size: %ld!\n", circular_buf_size(thread_circ_buf));
        if (circular_buf_size(thread_circ_buf) == 0)
        {
            fprintf(fp_log, "TIMEOUT_MGMT: Circular Buffer empty, thread blocked!\n");
            pthread_cond_wait(thread_cond_ptr, thread_g_tMutex_ptr);
        }

        // pthread_mutex_lock(thread_head_mutex_ptr);
        res = circular_buf_get(thread_circ_buf, &buf_slot);
#ifdef DO_STATS
        (*thread_circ_buf_count)--;
#endif
        /* Check the next timeout */
        if (res != -1)
        {
            pkt_desc_ptr = (pkt_desc_t *)buf_slot;
            /* The packet is freed before the sleep */
            if ((pkt_desc_ptr == NULL) || (pkt_desc_ptr->pkt_ptr == NULL))
            {
                fprintf(fp_log, "TIMEOUT_MGMT: Before sleeping skipped a packet descriptor which has already been freed.\n");
                continue;
            }
            else
            {
                ip_protocol = pkt_desc_ptr->pkt_ptr->addr_pair.protocol;
                /* Sleeping time calculation */
                pkt_time = pkt_desc_ptr->recv_time;
                gettimeofday(&current_time, NULL);
                time_diff = tv_sub_2(current_time, pkt_time);
                fprintf(fp_log, "type: %d, time_diff: %d\n", ip_protocol, time_diff);

                /* if (cur_time – pkt_time) <= Timeout, sleeps for (Timeout - (cur_time – pkt_time)) */
                if (thread_timeout >= time_diff)
                {
                    sleep_time_us = thread_timeout - time_diff;
                    // if (debug > 1)
                    // {
                    //     fprintf(fp_log, "TIMEOUT_MGMT: going to sleep for %dus!\n", sleep_time_us);
                    // }
                    usleep(sleep_time_us);
                }
                /* otherwise, the packet is delayed more than Timeout. The packet should to be freed immediately.
                 * Should try to not let this happen! */
                else
                {
                    // if (debug > 1)
                    // {
                    //     fprintf(fp_log, "TIMEOUT_MGMT: A type %d packet is delayed too long for %dus!!!\n", ip_protocol, time_diff);
                    // }
                }

                /* sleeping finishes, start cleaning */
                /* The packet could be freed during the sleeping, so we should check again after sleeping */
                if ((pkt_desc_ptr == NULL) || (pkt_desc_ptr->pkt_ptr == NULL))
                {
                    fprintf(fp_log, "TIMEOUT_MGMT: After sleeping skipped a packet descriptor which has already been freed.\n");
                    continue;
                }

                /* The packet descriptor and packet still exist. Start to clean. */
                flow_hash_ptr = pkt_desc_ptr->flow_hash_ptr;
                // if (debug > 1)
                // {
                //     char ip_src_addr_print_buffer[INET_ADDRSTRLEN], ip_dst_addr_print_buffer[INET_ADDRSTRLEN];
                //     inet_ntop(AF_INET, &(pkt_desc_ptr->pkt_ptr->addr_pair.a_address.un.ip4), ip_src_addr_print_buffer, INET_ADDRSTRLEN);
                //     inet_ntop(AF_INET, &(pkt_desc_ptr->pkt_ptr->addr_pair.b_address.un.ip4), ip_dst_addr_print_buffer, INET_ADDRSTRLEN);
                //     fprintf(fp_log, "TIMEOUT_MGMT: popping TCP SYN: from %s:%d to %s:%d with %d bytes of raw packet %c%c.. at %ld.%5ld\n",
                //             ip_src_addr_print_buffer,
                //             (pkt_desc_ptr)->pkt_ptr->addr_pair.a_port,
                //             ip_dst_addr_print_buffer,
                //             (pkt_desc_ptr)->pkt_ptr->addr_pair.b_port,
                //             (pkt_desc_ptr)->pkt_ptr->pkt_len,
                //             (pkt_desc_ptr)->pkt_ptr->raw_pkt[0],
                //             (pkt_desc_ptr)->pkt_ptr->raw_pkt[1],
                //             current_time.tv_sec,
                //             current_time.tv_usec);
                // }

                if (SendPkt(pkt_desc_ptr->pkt_ptr->raw_pkt, pkt_desc_ptr->pkt_ptr->pkt_len) == -1)
                {
                    fprintf(fp_log, "TIMEOUT_MGMT: Error: Cannot send the packet!\n");
                }
                FreePkt(pkt_desc_ptr->pkt_ptr);
                FreePktDesc(pkt_desc_ptr);
                FreeFlowHash(flow_hash_ptr);


#ifdef DO_STATS
                pkt_buf_count--;
                flow_hash_count--;
                pkt_desc_count--;
                expired_pkt_count_tot++;
                switch (ip_protocol)
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
#endif
            }
        }
        // pthread_mutex_unlock(thread_head_mutex_ptr);
    }
}