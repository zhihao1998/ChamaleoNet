#include "shm_rule_ring.h"

#include <fcntl.h>
#include <sched.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

/* Header layout offsets (little-endian host on Linux/x86_64). */
#define OFF_MAGIC 0u
#define OFF_VERSION 4u
#define OFF_CAPACITY 8u
#define OFF_FLAGS 12u
#define OFF_HEAD 16u
#define OFF_TAIL 20u
#define OFF_LOCK 24u
#define OFF_DROPPED 28u
#define OFF_PUSHES 32u
#define OFF_POPS 40u

static inline uint32_t rd_u32(const volatile uint8_t *base, uint32_t off)
{
    uint32_t v;
    memcpy(&v, (const void *)(base + off), sizeof(v));
    return v;
}

static inline uint64_t rd_u64(const volatile uint8_t *base, uint32_t off)
{
    uint64_t v;
    memcpy(&v, (const void *)(base + off), sizeof(v));
    return v;
}

static inline void wr_u32(volatile uint8_t *base, uint32_t off, uint32_t v)
{
    memcpy((void *)(base + off), &v, sizeof(v));
}

static inline void wr_u64(volatile uint8_t *base, uint32_t off, uint64_t v)
{
    memcpy((void *)(base + off), &v, sizeof(v));
}

static int lock_ring(volatile uint8_t *hdr)
{
    volatile uint32_t *lockp = (volatile uint32_t *)(void *)(hdr + OFF_LOCK);
    for (int i = 0; i < 10000; ++i) {
        if (__sync_lock_test_and_set(lockp, 1u) == 0u) {
            return 0;
        }
        sched_yield();
    }
    return -1;
}

static inline void unlock_ring(volatile uint8_t *hdr)
{
    volatile uint32_t *lockp = (volatile uint32_t *)(void *)(hdr + OFF_LOCK);
    __sync_lock_release(lockp);
}

int shm_rule_ring_open(shm_rule_ring_t *ring, const char *name, uint32_t capacity)
{
    if (!ring || !name || name[0] != '/' || capacity < 1024u) {
        return -1;
    }

    memset(ring, 0, sizeof(*ring));
    ring->fd = -1;

    const size_t map_len = SHM_RULE_RING_HDR_SIZE + (size_t)capacity * sizeof(shm_rule_slot_t);
    int fd = shm_open(name, O_RDWR | O_CREAT, 0666);
    if (fd < 0) {
        return -1;
    }
    /* shm_open mode is filtered by process umask; force world rw so
     * non-root controller and root tsdn workers can share the same ring. */
    (void)fchmod(fd, 0666);
    if (ftruncate(fd, (off_t)map_len) != 0) {
        close(fd);
        return -1;
    }

    void *base = mmap(NULL, map_len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (base == MAP_FAILED) {
        close(fd);
        return -1;
    }

    volatile uint8_t *hdr = (volatile uint8_t *)base;
    if (rd_u32(hdr, OFF_MAGIC) != SHM_RULE_RING_MAGIC ||
        rd_u32(hdr, OFF_VERSION) != SHM_RULE_RING_VERSION ||
        rd_u32(hdr, OFF_CAPACITY) != capacity) {
        memset(base, 0, map_len);
        wr_u32(hdr, OFF_CAPACITY, capacity);
        wr_u32(hdr, OFF_VERSION, SHM_RULE_RING_VERSION);
        wr_u32(hdr, OFF_MAGIC, SHM_RULE_RING_MAGIC);
    }

    ring->fd = fd;
    ring->map_len = map_len;
    ring->map_base = base;
    ring->hdr = hdr;
    ring->slots = (volatile shm_rule_slot_t *)((volatile uint8_t *)base + SHM_RULE_RING_HDR_SIZE);
    ring->capacity = rd_u32(hdr, OFF_CAPACITY);
    return 0;
}

void shm_rule_ring_close(shm_rule_ring_t *ring)
{
    if (!ring) {
        return;
    }
    if (ring->map_base && ring->map_len) {
        munmap(ring->map_base, ring->map_len);
    }
    if (ring->fd >= 0) {
        close(ring->fd);
    }
    memset(ring, 0, sizeof(*ring));
    ring->fd = -1;
}

int shm_rule_ring_push(shm_rule_ring_t *ring, uint32_t ip, uint16_t port, uint8_t proto)
{
    if (!ring || !ring->hdr || !ring->slots || ring->capacity == 0) {
        return -1;
    }
    if (lock_ring(ring->hdr) != 0) {
        return -1;
    }

    const uint32_t cap = ring->capacity;
    const uint32_t head = rd_u32(ring->hdr, OFF_HEAD);
    const uint32_t tail = rd_u32(ring->hdr, OFF_TAIL);
    const uint32_t next = (tail + 1u) % cap;
    if (next == head) {
        const uint32_t dropped = rd_u32(ring->hdr, OFF_DROPPED);
        wr_u32(ring->hdr, OFF_DROPPED, dropped + 1u);
        unlock_ring(ring->hdr);
        return -1;
    }

    shm_rule_slot_t slot;
    slot.proto = proto;
    slot.reserved = 0;
    slot.port = port;
    slot.ipv4 = ip;
    memcpy((void *)&ring->slots[tail], &slot, sizeof(slot));
    __sync_synchronize();
    wr_u32(ring->hdr, OFF_TAIL, next);
    wr_u64(ring->hdr, OFF_PUSHES, rd_u64(ring->hdr, OFF_PUSHES) + 1u);
    unlock_ring(ring->hdr);
    return 0;
}

