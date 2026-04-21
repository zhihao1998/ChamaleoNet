#include "tsdn.h"
#include "shm_rule_ring.h"
#include <errno.h>

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
static int g_sink_use_shm = 0;
static char g_shm_name[128] = {0};
static shm_rule_ring_t g_shm_ring;

static inline uint64_t now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + ts.tv_nsec;
}

int p4_batch_init(const char *uds_path)
{
    if (g_sink_use_shm) {
        return 0;
    }
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

/* Same as p4_batch_add_rule but skips dedup (caller already did it). */
static int p4_batch_add_rule_raw(uint32_t ip, uint16_t port, uint8_t proto)
{
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
    r->port = port;
    r->ipv4 = ip;

    return 0;
}

int p4_batch_add_rule(uint32_t ip, uint16_t port, uint8_t proto)
{
    if (!dedup_should_send(ip, port, proto, 1000)) {
        return 2;
    }
    return p4_batch_add_rule_raw(ip, port, proto);
}

int p4_batch_flush(void)
{
    install_rule_batch_count++;
    if (g_count == 0) return 0;

    if (g_sink_use_shm) {
        uint16_t sent = 0;
        for (uint16_t i = 0; i < g_count; ++i) {
            p4_rule_t *r = &g_rules[i];
            if (shm_rule_ring_push(&g_shm_ring, r->ipv4, r->port, r->proto) != 0) {
                break;
            }
            sent++;
        }
        if (sent == 0) {
            return 1;
        }
        if (sent < g_count) {
            memmove(g_rules, g_rules + sent, (size_t)(g_count - sent) * sizeof(p4_rule_t));
            g_count -= sent;
            clock_gettime(CLOCK_MONOTONIC, &g_last_flush_ts);
            return 1;
        }
        g_count = 0;
        clock_gettime(CLOCK_MONOTONIC, &g_last_flush_ts);
        return 0;
    }

    if (g_sock == -1) return -1;

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

/* ---------------------------------------------------------------------------
 * Rule install queue: packet thread pushes, install thread pops.
 * Keeps rule installation off the critical packet processing path.
 * --------------------------------------------------------------------------- */
#define RULE_QUEUE_SIZE 65536

typedef struct {
    uint32_t ip;
    uint16_t port;
    uint8_t proto;
} rule_req_t;

static rule_req_t rule_queue[RULE_QUEUE_SIZE];
static uint32_t rule_queue_head;
static uint32_t rule_queue_tail;
static pthread_mutex_t rule_queue_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t rule_queue_cond = PTHREAD_COND_INITIALIZER;
static volatile int rule_queue_shutdown = 0;

/* Non-blocking push. Returns 0 on success, -1 if queue full.
 * Called from packet processing path - must be fast. */
int rule_queue_push(uint32_t ip, uint16_t port, uint8_t proto)
{
    pthread_mutex_lock(&rule_queue_mutex);
    uint32_t next = (rule_queue_tail + 1) % RULE_QUEUE_SIZE;
    if (next == rule_queue_head) {
        pthread_mutex_unlock(&rule_queue_mutex);
        return -1; /* full */
    }
    rule_queue[rule_queue_tail].ip = ip;
    rule_queue[rule_queue_tail].port = port;
    rule_queue[rule_queue_tail].proto = proto;
    rule_queue_tail = next;
    pthread_cond_signal(&rule_queue_cond);
    pthread_mutex_unlock(&rule_queue_mutex);
    return 0;
}

uint32_t rule_queue_depth(void)
{
    pthread_mutex_lock(&rule_queue_mutex);
    uint32_t h = rule_queue_head;
    uint32_t t = rule_queue_tail;
    pthread_mutex_unlock(&rule_queue_mutex);
    return (t + RULE_QUEUE_SIZE - h) % RULE_QUEUE_SIZE;
}
/* Pop one item. Blocks with timeout until item available or shutdown.
 * Returns 0 on success, -1 on shutdown, 1 on empty (should not happen when blocking). */
static int rule_queue_pop(rule_req_t *out)
{
    struct timespec ts;
    pthread_mutex_lock(&rule_queue_mutex);
    for (;;) {
        if (rule_queue_shutdown) {
            pthread_mutex_unlock(&rule_queue_mutex);
            return -1;
        }
        if (rule_queue_head != rule_queue_tail) {
            out->ip = rule_queue[rule_queue_head].ip;
            out->port = rule_queue[rule_queue_head].port;
            out->proto = rule_queue[rule_queue_head].proto;
            rule_queue_head = (rule_queue_head + 1) % RULE_QUEUE_SIZE;
            pthread_mutex_unlock(&rule_queue_mutex);
            return 0;
        }
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec += 1;
        pthread_cond_timedwait(&rule_queue_cond, &rule_queue_mutex, &ts);
    }
}

static void *entry_install_thread_func(void *arg)
{
    const char *uds_path = (const char *)arg;
    rule_req_t req;

    if (!g_sink_use_shm) {
        p4_batch_init(uds_path);
    }

    while (rule_queue_pop(&req) == 0) {
        int res = p4_batch_add_rule_raw(req.ip, req.port, req.proto);
        if (res != -1) {
            __sync_fetch_and_add(&controller_rule_install_count, 1);
        }
    }
    return NULL;
}

static pthread_t g_entry_install_thread;

void entry_install_thread_start(const char *uds_path)
{
    const char *shm_name = getenv("P4_RULE_SHM_NAME");
    if (shm_name && shm_name[0] == '/') {
        strncpy(g_shm_name, shm_name, sizeof(g_shm_name) - 1);
        g_shm_name[sizeof(g_shm_name) - 1] = '\0';
        if (shm_rule_ring_open(&g_shm_ring, g_shm_name, 262144u) == 0) {
            g_sink_use_shm = 1;
            log_info("entry install sink: SHM %s", g_shm_name);
        } else {
            g_sink_use_shm = 0;
            log_warn("failed to open SHM ring %s, fallback to UDS", g_shm_name);
        }
    } else {
        g_sink_use_shm = 0;
    }

    rule_queue_shutdown = 0;
    rule_queue_head = 0;
    rule_queue_tail = 0;
    pthread_create(&g_entry_install_thread, NULL, entry_install_thread_func,
                   (void *)uds_path);
}

void entry_install_thread_stop(void)
{
    pthread_mutex_lock(&rule_queue_mutex);
    rule_queue_shutdown = 1;
    pthread_cond_broadcast(&rule_queue_cond);
    pthread_mutex_unlock(&rule_queue_mutex);
    pthread_join(g_entry_install_thread, NULL);
    if (g_sink_use_shm) {
        shm_rule_ring_close(&g_shm_ring);
    }
}
