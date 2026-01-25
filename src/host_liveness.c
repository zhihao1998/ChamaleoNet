
#include "tsdn.h"

#ifdef HOST_LIVENESS_MONITOR
/* Active Host List. */
struct timeval last_active_entry_update_time;
struct timeval last_active_host_merge_time;

uint8_t active_internal_host_entry[INTERNAL_HOST_NUM];
uint8_t active_internal_host_send[INTERNAL_HOST_NUM];
uint8_t active_internal_host[INTERNAL_HOST_NUM];

void merge_host_liveness(void)
{
    pthread_mutex_lock(&active_internal_host_entry_mutex);
    for (size_t i = 0; i < INTERNAL_HOST_NUM; i++)
    {
        active_internal_host[i] = active_internal_host_send[i] | active_internal_host_entry[i];
    }
    pthread_mutex_unlock(&active_internal_host_entry_mutex);
}

uint8_t check_internal_host_liveness(uint32_t ip_src)
{
    uint32_t offset = ip_src - base_ip_int;
    // printf("%" PRIu32 " ,%" PRIu32 " ,%" PRIu32 "\n", pip->ip_src.s_addr, base_ip_int, offset);
    return active_internal_host[offset];
}

uint32_t count_active_hosts()
{
    uint32_t count = 0;
    for (int i = 0; i < INTERNAL_HOST_NUM; ++i)
    {
        count += active_internal_host[i];
    }
    return count;
}

int append_host_alive_after_l4(
    struct ether_header *peth,
    struct ip *pip,
    int tlen,
    uint8_t host_alive)
{
    if (!peth || !pip) {
        return -1;
    }

    /* IPv4 header 长度 */
    size_t ip_hlen = (size_t)pip->ip_hl * 4;

    /* 至少要有：ETH + IP */
    if ((size_t)tlen < ETH_HLEN + ip_hlen) {
        return -1;
    }

    uint8_t *l4 = (uint8_t *)pip + ip_hlen;

    switch (pip->ip_p)
    {
        case IPPROTO_TCP:
        {
            if ((size_t)tlen < ETH_HLEN + ip_hlen + sizeof(struct tcphdr)) {
                return -1;
            }

            struct tcphdr *tcp = (struct tcphdr *)l4;
            size_t tcp_hlen = (size_t)tcp->doff * 4;

            if (tcp_hlen < sizeof(struct tcphdr)) {
                return -1;
            }

            /* 需要至少 1 字节 payload */
            if ((size_t)tlen < ETH_HLEN + ip_hlen + tcp_hlen + 1) {
                return -1;
            }

            uint8_t *payload = (uint8_t *)tcp + tcp_hlen;
            payload[0] = host_alive;
            return 0;
        }

        case IPPROTO_UDP:
        {
            if ((size_t)tlen < ETH_HLEN + ip_hlen + sizeof(struct udphdr) + 1) {
                return -1;
            }

            struct udphdr *udp = (struct udphdr *)l4;
            uint8_t *payload = (uint8_t *)udp + sizeof(struct udphdr);
            payload[0] = host_alive;
            return 0;
        }

        case IPPROTO_ICMP:
        {
            if ((size_t)tlen < ETH_HLEN + ip_hlen + sizeof(struct icmphdr) + 1) {
                return -1;
            }

            struct icmphdr *icmp = (struct icmphdr *)l4;
            uint8_t *payload = (uint8_t *)icmp + sizeof(struct icmphdr);
            payload[0] = host_alive;
            return 0;
        }

        default:
            return -1;
    }
}

int append_host_alive_to_tos(
    struct ether_header *peth,
    struct ip *pip,
    int tlen,
    uint8_t host_alive)
{
    if (!peth || !pip) {
        return -1;
    }

    /* IPv4 header 最小 20 字节 */
    size_t ip_hlen = (size_t)pip->ip_hl * 4;
    if (ip_hlen < sizeof(struct ip)) {
        return -1;
    }

    /* 至少要有：ETH + IP header */
    if ((size_t)tlen < ETH_HLEN + ip_hlen) {
        return -1;
    }

    /* 直接写入 TOS 字段 */
    pip->ip_tos = host_alive;

    return 0;
}


#endif
