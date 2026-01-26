#include "tsdn.h"

#define P4_MAGIC 0x5034  // 'P4'
#define P4_VER   1
#define P4_OP_INSTALL 1

// 单个 datagram 建议 < 64KB，稳妥起见控制在 ~32KB
// header 8B + N*8B => N=4000 时是 32008B，很安全
#define P4_MAX_RULES_PER_MSG 4000

typedef struct __attribute__((packed)) {
    uint16_t magic;
    uint8_t  version;
    uint8_t  op;
    uint16_t count;     // network order
    uint16_t reserved;
} p4_batch_hdr_t;

typedef struct __attribute__((packed)) {
    uint8_t  proto;
    uint8_t  reserved;
    uint16_t port;      // network order
    uint32_t ipv4;      // network order
} p4_rule_t;

_Static_assert(sizeof(p4_batch_hdr_t) == 8, "hdr must be 8");
_Static_assert(sizeof(p4_rule_t) == 8, "rule must be 8");

// 每线程一份 buffer：避免多线程锁竞争/缓存抖动
static __thread int g_sock = -1;
static __thread struct sockaddr_un g_addr;
static __thread p4_rule_t g_rules[P4_MAX_RULES_PER_MSG];
static __thread uint16_t g_count = 0;
static __thread struct timespec g_last_flush_ts = {0, 0};

static inline uint64_t now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + ts.tv_nsec;
}

int p4_batch_init(const char *uds_path)
{
    if (g_sock != -1) return 0;

    g_sock = socket(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    if (g_sock < 0) return -1;

    int snd = 4 * 1024 * 1024;
    setsockopt(g_sock, SOL_SOCKET, SO_SNDBUF, &snd, sizeof(snd));

    memset(&g_addr, 0, sizeof(g_addr));
    g_addr.sun_family = AF_UNIX;
    strncpy(g_addr.sun_path, uds_path, sizeof(g_addr.sun_path) - 1);

    g_count = 0;
    clock_gettime(CLOCK_MONOTONIC, &g_last_flush_ts);
    return 0;
}


#define FLUSH_INTERVAL_NS (10ull * 1000 * 1000)  // 10ms

int p4_batch_add_rule(struct in_addr ip, uint16_t port_host, uint8_t proto)
{
    replied_flow_count_tot++;
    if (!dedup_should_send(ip.s_addr, port_host, proto, 1000)) {
        return 2;
    }

    if (g_sock == -1) {
        if (p4_batch_init("/tmp/p4_controller.sock") != 0)
            return -1;
    }

    uint64_t now = now_ns();
    uint64_t last = (uint64_t)g_last_flush_ts.tv_sec * 1000000000ull
                  + g_last_flush_ts.tv_nsec;

    /* 条件 1：时间到了，立马推 */
    if (g_count > 0 && now - last >= FLUSH_INTERVAL_NS) {
        int rc = p4_batch_flush();
        if (rc == 1) {
            return 1;  // socket 满，保留队列
        }
        if (rc < 0) {
            return rc;
        }
    }

    /* 条件 2：队列满了，立马推 */
    if (g_count >= P4_MAX_RULES_PER_MSG) {
        int rc = p4_batch_flush();
        if (rc != 0) {
            return rc;
        }
    }

    p4_rule_t *r = &g_rules[g_count++];
    r->proto = proto;
    r->reserved = 0;
    r->port = port_host;
    r->ipv4 = ip.s_addr;

    return 0;
}

int p4_batch_flush(void)
{
    install_rule_batch_count++;
    if (g_sock == -1) return -1;
    if (g_count == 0) return 0;

    const size_t hdr_sz = sizeof(p4_batch_hdr_t);
    const size_t rules_sz = (size_t)g_count * sizeof(p4_rule_t);
    const size_t total_sz = hdr_sz + rules_sz;

    uint8_t buf[8 + P4_MAX_RULES_PER_MSG * 8];

    p4_batch_hdr_t hdr = {
        .magic = htons(P4_MAGIC),
        .version = P4_VER,
        .op = P4_OP_INSTALL,
        .count = htons(g_count),
        .reserved = 0,
    };

    memcpy(buf, &hdr, hdr_sz);
    memcpy(buf + hdr_sz, g_rules, rules_sz);

    ssize_t n = sendto(g_sock, buf, total_sz, MSG_DONTWAIT,
                       (struct sockaddr *)&g_addr, sizeof(g_addr));

    if (n == (ssize_t)total_sz) {
        g_count = 0;
        clock_gettime(CLOCK_MONOTONIC, &g_last_flush_ts);
        return 0;
    }

    if (errno == EAGAIN || errno == EWOULDBLOCK || errno == ENOBUFS) {
        return 1;
    }

    return -1;
}
