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

#include "tsdn.h"

/*
** Memory management with freelist instead of malloc and free.
**
*/
extern Bool bayes_engine;

#ifdef MEMDEBUG
long IN_USE_TP = 0;
long IN_USE_SEGMENT = 0;
long IN_USE_QUADRANT = 0;
long IN_USE_PTP_SNAP = 0;
long IN_USE_UDP_PAIR = 0;

long TOT_TP = 0;
long TOT_SEGMENT = 0;
long TOT_QUADRANT = 0;
long TOT_PTP_SNAP = 0;
long TOT_UDP_PAIR = 0;
extern long tot_adx_hash_count, bayes_new_count;

void memory_debug()
{
  fprintf(fp_stdout, "Using %ld over %ld TP\t(%ldK) (%ld MAX)\n",
          IN_USE_TP, TOT_TP, GLOBALS.Max_TCP_Packets, TOT_TP * sizeof(tcp_packet) >> 10);
  fprintf(fp_stdout, "Using %ld over %ld SEGMENT\t(%ldK)\n",
          IN_USE_SEGMENT, TOT_SEGMENT, TOT_SEGMENT * sizeof(segment) >> 10);
  fprintf(fp_stdout, "Using %ld over %ld QUADRANT\t(%ldK)\n",
          IN_USE_QUADRANT, TOT_QUADRANT, TOT_QUADRANT * sizeof(quadrant) >> 10);
  fprintf(fp_stdout, "Using %ld over %ld PTP_SNAP\t(%ldK)\n",
          IN_USE_PTP_SNAP, TOT_PTP_SNAP, TOT_PTP_SNAP * sizeof(ptp_snap) >> 10);
  fprintf(fp_stdout, "Using %ld over %ld UDP_PAIR\t(%ldK)\n",
          IN_USE_UDP_PAIR, TOT_UDP_PAIR, TOT_UDP_PAIR * sizeof(udp_pair) >> 10);
  fprintf(fp_stdout, "Using %ld ADX\n", tot_adx_hash_count);
  fprintf(fp_stdout, "Using %ld bayes_classifier\n", bayes_new_count);
}
#endif
/*
**  Function  : void *MMmalloc(size_t size, const char * function_name)
**  Return    : the pointer to the memory of the new allocated block
**  Remarks   : MMmalloc() allocates size bytes and returns a pointer to the
**              allocated memory.  The memory is cleared.
**              If an error occours, an error is printed, including the
**              function name of the calling function.
*/
void *
MMmalloc(size_t size, const char *f_name)
{
  void *temp_pointer;
  if ((temp_pointer = malloc(size)) == NULL)
  {
    /* If problems arise from the memory allocation, an error message is    */
    /* printed before exiting the program execution.                        */
    fprintf(stderr,
            "\nError:  Memory allocation error in Tstat function %s\n", f_name);
    exit(1);
  }
  memset(temp_pointer, 0, size);
  return temp_pointer;
}

/* Garbage collector for the tcp_packet structs
 * Two pointer are used (top and last).
 * Alloc and release from last, while top is used to not loose the list ...
 */

static struct tp_list_elem *top_tp_flist = NULL;  /* Pointer to the top of      */
                                                  /* the 'tplist' free list.    */
static struct tp_list_elem *last_tp_flist = NULL; /* Pointer to the last used   */
                                                  /* element list.              */

tcp_packet *
tp_alloc(void)
{
  tcp_packet *ptp_temp;
#ifdef MEMDEBUG
  IN_USE_TP++;
#endif

  if ((last_tp_flist == NULL) || (last_tp_flist->ptp == NULL))
  { /* The LinkList stack is empty.         */
    /* fprintf (fp_stdout, "FList empty, top == last == NULL\n"); */
    ptp_temp = (tcp_packet *)MMmalloc(sizeof(tcp_packet), "tplist_alloc");
#ifdef MEMDEBUG
    TOT_TP++;
#endif

    return ptp_temp;
  }
  else
  { /* The 'tplist' stack is not empty.   */
    ptp_temp = last_tp_flist->ptp;
    last_tp_flist->ptp = NULL;
    if (last_tp_flist->next != NULL)
      last_tp_flist = last_tp_flist->next;
    return ptp_temp;
  }
}

void tp_release(tcp_packet *released_tcp_packet)
{
  struct tp_list_elem *new_tplist_elem;
  seqspace *sstemp1, *sstemp2;

#ifdef MEMDEBUG
  IN_USE_TP--;
#endif

  memset(released_tcp_packet, 0, sizeof(tcp_packet));

  if ((last_tp_flist == NULL) || ((last_tp_flist->ptp != NULL) && (last_tp_flist->prev == NULL)))
  {

    new_tplist_elem =
        (struct tp_list_elem *)MMmalloc(sizeof(struct tp_list_elem),
                                        "tplist_release");
    new_tplist_elem->ptp = released_tcp_packet;
    new_tplist_elem->prev = NULL;
    new_tplist_elem->next = top_tp_flist;
    if (new_tplist_elem->next != NULL)
      new_tplist_elem->next->prev = new_tplist_elem;
    top_tp_flist = new_tplist_elem;
    last_tp_flist = new_tplist_elem;
  }
  else
  {
    if (last_tp_flist->ptp == NULL)
      new_tplist_elem = last_tp_flist;
    else
      new_tplist_elem = last_tp_flist->prev;
    new_tplist_elem->ptp = released_tcp_packet;
    last_tp_flist = new_tplist_elem;
  }
}

void tp_list_list()
{
  struct tp_list_elem *new_tplist_elem;

  new_tplist_elem = top_tp_flist;
  fprintf(fp_stdout, "\n\t[top]\n");
  while (new_tplist_elem != NULL)
  {
    fprintf(fp_stdout, "\t|\n");
    if (new_tplist_elem == last_tp_flist)
      fprintf(fp_stdout, "[last]->");
    else
      fprintf(fp_stdout, "\t");
    fprintf(fp_stdout, "[tp_list_elem]->");
    if (new_tplist_elem->ptp != NULL)
    {
      fprintf(fp_stdout, "[ptp]");
    }
    else
    {
      fprintf(fp_stdout, "[NULL]");
    }
    fprintf(fp_stdout, "\n");
    new_tplist_elem = new_tplist_elem->next;
  }
  fprintf(fp_stdout, "\n");
}

/* garbage collector for the segment list */

static segment *segment_flist = NULL; /* Pointer to the top of      */
                                      /* the 'segment' free list.  */
segment *
segment_alloc(void)
{
  segment *pseg;

#ifdef MEMDEBUG
  IN_USE_SEGMENT++;
#endif
  if (segment_flist == NULL)
  {
    pseg = (segment *)MallocZ(sizeof(segment));
#ifdef MEMDEBUG
    TOT_SEGMENT++;
#endif
  }
  else
  {
    pseg = segment_flist;
    segment_flist = segment_flist->next;
  }
  pseg->next = NULL;
  return pseg;
}

void segment_release(segment *rel_segment)
{
#ifdef MEMDEBUG
  IN_USE_SEGMENT--;
#endif
  memset(rel_segment, 0, sizeof(segment));
  rel_segment->next = segment_flist;
  segment_flist = rel_segment;
}

void segment_list_info()
{
  segment *pseg;
  int i = 0;

  pseg = segment_flist;
  while (pseg != NULL)
  {
    i++;
    pseg = pseg->next;
  }
  fprintf(fp_stdout, "Segments in flist: %d\n", i);
}

/* garbage collector for the Quadrant */

static quadrant *quadrant_flist = NULL; /* Pointer to the top of      */
                                        /* the 'quadrant' free list.  */

quadrant *
quadrant_alloc(void)
{
  quadrant *pquad;

#ifdef MEMDEBUG
  IN_USE_QUADRANT++;
#endif
  if (quadrant_flist == NULL)
  {
    pquad = (quadrant *)MallocZ(sizeof(quadrant));
#ifdef MEMDEBUG
    TOT_QUADRANT++;
#endif
  }
  else
  {
    pquad = quadrant_flist;
    quadrant_flist = quadrant_flist->next;
  }
  pquad->next = NULL;
  return pquad;
}

void quadrant_release(quadrant *rel_quadrant)
{
#ifdef MEMDEBUG
  IN_USE_QUADRANT--;
#endif
  memset(rel_quadrant, 0, sizeof(quadrant));
  rel_quadrant->next = quadrant_flist;
  quadrant_flist = rel_quadrant;
}

void quadrant_list_info()
{
  quadrant *pquad;
  int i = 0;

  pquad = quadrant_flist;
  while (pquad != NULL)
  {
    i++;
    pquad = pquad->next;
  }
  fprintf(fp_stdout, "Quadrants in flist: %d\n", i);
}

/* garbage collector for the ptp_snap list */

static ptp_snap *top_ptph_flist = NULL; /* Pointer to the top of      */
                                        /* the 'ptp_snap' free list.    */
ptp_snap *ptph_alloc(void)
{
  struct ptp_snap *new_ptph;

#ifdef MEMDEBUG
  IN_USE_PTP_SNAP++;
#endif

  if (top_ptph_flist == NULL)
  {
    new_ptph = (ptp_snap *)MMmalloc(sizeof(ptp_snap), "ptph_alloc");
#ifdef MEMDEBUG
    TOT_PTP_SNAP++;
#endif
  }
  else
  {
    new_ptph = top_ptph_flist;
    top_ptph_flist = top_ptph_flist->next;
  }
  new_ptph->next = NULL;
  return (new_ptph);
}

void ptph_release(ptp_snap *rel_ptph)
{
#ifdef MEMDEBUG
  IN_USE_PTP_SNAP--;
#endif
  memset(rel_ptph, 0, sizeof(ptp_snap));
  rel_ptph->next = top_ptph_flist;
  top_ptph_flist = rel_ptph;
}

int UsingFreedPtpsnap(ptp_snap *my_ptph)
{
  struct ptp_snap *temp_ptph;

  temp_ptph = top_ptph_flist;
  while (temp_ptph)
  {
    if (temp_ptph == my_ptph)
      return (1);
    temp_ptph = temp_ptph->next;
  }
  return (0);
}
