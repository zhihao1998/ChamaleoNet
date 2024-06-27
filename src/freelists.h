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

segment *segment_alloc (void);
void segment_release (segment *);
void segment_list_info (void);

quadrant *quadrant_alloc (void);
void quadrant_release (quadrant *);
void quadrant_list_info (void);

tcp_packet *tp_alloc (void);
void tp_release (tcp_packet * relesased_tcp_packet);

ptp_snap *ptph_alloc (void);
void ptph_release (ptp_snap * rel_ptph);
void *MMmalloc (size_t size, const char *f_name);

// udp_pair *utp_alloc (void);
// void utp_release (udp_pair * rel_udp_pair);
