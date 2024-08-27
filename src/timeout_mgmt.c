#include "tsdn.h"

/* timeout_mgmt thread */
void *timeout_mgmt(void *args)
{
    timeout_mgmt_args *timeout_mgmt_args_ptr = (timeout_mgmt_args *)args;
    int thread_timeout = timeout_mgmt_args_ptr->timeout;
    circular_buf_t *thread_circ_buf = timeout_mgmt_args_ptr->circ_buf;
    pthread_mutex_t *thread_g_tMutex_ptr = timeout_mgmt_args_ptr->g_tMutex_ptr;
    pthread_cond_t *thread_cond_ptr = timeout_mgmt_args_ptr->cond_ptr;

    while (circular_buf_empty(thread_circ_buf))
    {
        fprintf(fp_stdout, "TIMEOUT_MGMT: Circular Buffer empty, thread blocked!\n");
        pthread_cond_wait(thread_cond_ptr, thread_g_tMutex_ptr);
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
        // fprintf(fp_stderr, "TIMEOUT_MGMT: size: %ld!\n", circular_buf_size(thread_circ_buf));
        if (circular_buf_size(thread_circ_buf) == 0)
        {
            fprintf(fp_stdout, "TIMEOUT_MGMT: Circular Buffer empty, thread blocked!\n");
            pthread_cond_wait(thread_cond_ptr, thread_g_tMutex_ptr);
        }

        /* Check the next timeout */
        if (circular_buf_get(thread_circ_buf, &pkt_desc_ptr) != -1)
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
                if (thread_timeout >= time_diff)
                {
                    sleep_time_us = thread_timeout - time_diff;
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
                hval = pkt_desc_ptr->pkt_ptr->addr_pair.hash % HASH_TABLE_SIZE;
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
                    // fprintf(fp_stderr, "TIMEOUT_MGMT: size: %ld!\n", circular_buf_size(thread_circ_buf));
                }
                else
                {
                    fprintf(fp_stderr, "TIMEOUT_MGMT: Error: Cannot find the flow in the hash table!\n");
                }
            }
        }
    }
}