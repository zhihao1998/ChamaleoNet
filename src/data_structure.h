/*
 *
 * Copyright (c) 2001
 *	Politecnico di Torino.  All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * For bug report and other information please visit Tstat site:
 * http://tstat.polito.it
 *
 * Tstat is deeply based on TCPTRACE. The authors would like to thank
 * Shawn Ostermann for the development of TCPTRACE.
 *
*/

/* memory management and garbage collection routines */

struct tp_list_elem
{
  struct tp_list_elem *next;
  struct tp_list_elem *prev;
  tcp_packet *ptp;
};

struct tp_list_elem *tplist_alloc (void);
void tplist_release (struct tp_list_elem *rel_tplist);

tcp_packet *tp_alloc (void);
void tp_release (tcp_packet * relesased_tcp_packet);

ptp_snap *ptph_alloc (void);
void ptph_release (ptp_snap * rel_ptph);
void *MMmalloc (size_t size, const char *f_name);

/* Pkt descriptor */
pkt_desc_t *pkt_desc_alloc();
void pkt_desc_release(pkt_desc_t *rel_pkt_desc);

/* Flow hash table */
flow_hash *flow_hash_alloc();
void flow_hash_release(flow_hash *flow_hash_ptr);

/* Circular Buffer Related */

// Opaque circular buffer structure
typedef struct circular_buf_t circular_buf_t;

// Handle type, the way users interact with the API
// typedef circular_buf_t* cbuf_handle_t;

/// Pass in a storage buffer and size 
/// Returns a circular buffer handle
circular_buf_t* circular_buf_init(pkt_desc_t ** pkt_desc_buf, size_t size);

/// Free a circular buffer structure.
/// Does not free data buffer; owner is responsible for that
void circular_buf_free(circular_buf_t* me);

/// Reset the circular buffer to empty, head == tail
void circular_buf_reset(circular_buf_t* me);

/// Put version 1 continues to add data
int circular_buf_try_put(circular_buf_t *me, struct pkt_desc_t *pkt_desc_ptr);

/// Retrieve a value from the buffer
/// Returns 0 on success, -1 if the buffer is empty
int circular_buf_get(circular_buf_t *me, struct pkt_desc_t **pkt_desc_ptr_ptr);

/// Returns true if the buffer is empty
Bool circular_buf_empty(circular_buf_t* me);

/// Returns true if the buffer is full
Bool circular_buf_full(circular_buf_t* me);

/// Returns the maximum capacity of the buffer
size_t circular_buf_capacity(circular_buf_t* me);

/// Returns the current number of elements in the buffer
size_t circular_buf_size(circular_buf_t* me);
