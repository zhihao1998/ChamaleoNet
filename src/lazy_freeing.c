#include "tsdn.h"

/* lazy_free_flow_hash thread */
void *lazy_free_flow_hash(void *args)
{
    while (circular_buf_empty(lazy_flow_hash_circ_buf))
    {
        fprintf(fp_stdout, "LAZY_FREE_FLOW_HASH: Circular Buffer empty, thread blocked!\n");
        pthread_cond_wait(&lazy_flow_hash_cond, &lazy_flow_hash_mutex);
    }
    flow_hash_t *flow_hash_ptr;
    void *buf_slot;
    struct timeval resp_time, current_time;
    int time_diff_us, sleep_time_us;

    while (1)
    {
        // fprintf(fp_stderr, "LAZY_FREE_FLOW_HASH: size: %ld!\n", circular_buf_size(lazy_flow_hash_circ_buf));
        if (circular_buf_size(lazy_flow_hash_circ_buf) == 0)
        {
            fprintf(fp_stdout, "LAZY_FREE_FLOW_HASH: Circular Buffer empty, thread blocked!\n");
            pthread_cond_wait(&lazy_flow_hash_cond, &lazy_flow_hash_mutex);
        }

        /* Check the next timeout */
        if (circular_buf_get(lazy_flow_hash_circ_buf, &buf_slot) != -1)
        {
            flow_hash_ptr = (flow_hash_t *)buf_slot;

            assert(flow_hash_ptr != NULL);
            assert(flow_hash_ptr->lazy_pending == TRUE);

            /* Sleeping time calculation */
            resp_time = flow_hash_ptr->resp_time;
            gettimeofday(&current_time, NULL);
            time_diff_us = tv_sub_2(current_time, resp_time);
            
            /* if (cur_time – pkt_time) <= Timeout, sleeps for (Timeout - (cur_time – pkt_time)) */
            if (LAZY_FREEING_TIMEOUT >= time_diff_us)
            {
                sleep_time_us = LAZY_FREEING_TIMEOUT - time_diff_us;
                usleep(sleep_time_us);
            }
            /* otherwise, the packet is delayed more than Timeout. The packet should to be freed immediately.
             * Should try to not let this happen! */
            else
            {
                if (debug > 1)
                {
                    fprintf(fp_stderr, "LAZY_FREE_FLOW_HASH: Packet delayed more than Timeout. Should try to not let this happen!\n");
                }
            }

            /* sleeping finishes, start cleaning */
            if (debug > 1)
            {
                char ip_src_addr_print_buffer[INET_ADDRSTRLEN], ip_dst_addr_print_buffer[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &(flow_hash_ptr->addr_pair.a_address.un.ip4), ip_src_addr_print_buffer, INET_ADDRSTRLEN);
                inet_ntop(AF_INET, &(flow_hash_ptr->addr_pair.b_address.un.ip4), ip_dst_addr_print_buffer, INET_ADDRSTRLEN);
                fprintf(fp_stderr, "LAZY_FREE_FLOW_HASH: Cleaning flow_hash_ptr: %p, src: %s, dst: %s\n", flow_hash_ptr, ip_src_addr_print_buffer, ip_dst_addr_print_buffer);
            }
            FreeFlowHash(flow_hash_ptr);
        }
    }
}