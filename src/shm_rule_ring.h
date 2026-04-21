#pragma once

#include <stdint.h>
#include <stddef.h>

#define SHM_RULE_RING_MAGIC 0x31515250u /* "PQR1" */
#define SHM_RULE_RING_VERSION 1u
#define SHM_RULE_RING_HDR_SIZE 64u

typedef struct __attribute__((packed)) {
    uint8_t proto;
    uint8_t reserved;
    uint16_t port;
    uint32_t ipv4;
} shm_rule_slot_t;

_Static_assert(sizeof(shm_rule_slot_t) == 8, "shm slot must be 8 bytes");

typedef struct {
    int fd;
    size_t map_len;
    void *map_base;
    volatile uint8_t *hdr;
    volatile shm_rule_slot_t *slots;
    uint32_t capacity;
} shm_rule_ring_t;

/* name must be POSIX shm style, e.g. "/p4_rule_ring". */
int shm_rule_ring_open(shm_rule_ring_t *ring, const char *name, uint32_t capacity);
void shm_rule_ring_close(shm_rule_ring_t *ring);

/* Returns 0 on success, -1 if full or error. */
int shm_rule_ring_push(shm_rule_ring_t *ring, uint32_t ip, uint16_t port, uint8_t proto);

