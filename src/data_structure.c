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

long TOT_TP = 0;
extern long tot_adx_hash_count, bayes_new_count;

void memory_debug()
{
  fprintf(fp_stdout, "Using %ld over %ld TP\t(%ldK) (%ld MAX)\n",
          IN_USE_TP, TOT_TP, MAX_TCP_PACKETS, TOT_TP * sizeof(ip_packet) >> 10);
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

/* Garbage collector for the ip_packet structs
 * Two pointer are used (top and last).
 * Alloc and release from last, while top is used to not loose the list ...
 */

static struct pkt_list_elem *top_pkt_flist = NULL;  /* Pointer to the top of      */
                                                  /* the 'pktlist' free list.    */
static struct pkt_list_elem *last_pkt_flist = NULL; /* Pointer to the last used   */
                                                  /* element list.              */

ip_packet *
pkt_alloc(void)
{
  ip_packet *ppkt_temp;
#ifdef MEMDEBUG
  IN_USE_TP++;
#endif

  if ((last_pkt_flist == NULL) || (last_pkt_flist->ppkt == NULL))
  { /* The LinkList stack is empty.         */
    /* fprintf (fp_stdout, "FList empty, top == last == NULL\n"); */
    ppkt_temp = (ip_packet *)MMmalloc(sizeof(ip_packet), "pktlist_alloc");
#ifdef MEMDEBUG
    TOT_TP++;
#endif

    return ppkt_temp;
  }
  else
  { /* The 'pktlist' stack is not empty.   */
    ppkt_temp = last_pkt_flist->ppkt;
    last_pkt_flist->ppkt = NULL;
    if (last_pkt_flist->next != NULL)
      last_pkt_flist = last_pkt_flist->next;
    return ppkt_temp;
  }
}

void pkt_release(ip_packet *released_ip_packet)
{
  struct pkt_list_elem *new_pktlist_elem;

#ifdef MEMDEBUG
  IN_USE_TP--;
#endif

  memset(released_ip_packet, 0, sizeof(ip_packet));

  if ((last_pkt_flist == NULL) || ((last_pkt_flist->ppkt != NULL) && (last_pkt_flist->prev == NULL)))
  {
    new_pktlist_elem =
        (struct pkt_list_elem *)MMmalloc(sizeof(struct pkt_list_elem),
                                        "pktlist_release");
    new_pktlist_elem->ppkt = released_ip_packet;
    new_pktlist_elem->prev = NULL;
    new_pktlist_elem->next = top_pkt_flist;
    if (new_pktlist_elem->next != NULL)
      new_pktlist_elem->next->prev = new_pktlist_elem;
    top_pkt_flist = new_pktlist_elem;
    last_pkt_flist = new_pktlist_elem;
  }
  else
  {
    if (last_pkt_flist->ppkt == NULL)
      new_pktlist_elem = last_pkt_flist;
    else
      new_pktlist_elem = last_pkt_flist->prev;
    new_pktlist_elem->ppkt = released_ip_packet;
    last_pkt_flist = new_pktlist_elem;
  }
}

void pkt_list_list()
{
  struct pkt_list_elem *new_pktlist_elem;

  new_pktlist_elem = top_pkt_flist;
  fprintf(fp_stdout, "\n\t[top]\n");
  while (new_pktlist_elem != NULL)
  {
    fprintf(fp_stdout, "\t|\n");
    if (new_pktlist_elem == last_pkt_flist)
      fprintf(fp_stdout, "[last]->");
    else
      fprintf(fp_stdout, "\t");
    fprintf(fp_stdout, "[pkt_list_elem]->");
    if (new_pktlist_elem->ppkt != NULL)
    {
      fprintf(fp_stdout, "[ppkt]");
    }
    else
    {
      fprintf(fp_stdout, "[NULL]");
    }
    fprintf(fp_stdout, "\n");
    new_pktlist_elem = new_pktlist_elem->next;
  }
  fprintf(fp_stdout, "\n");
}

/* Garbage collector for Packet Descriptor Array
 *  Two pointer are used (top and last).
 *  Alloc and release from last, while top is used to not loose the list ...
 */

static struct pkt_desc_list_elem *top_pkt_desc_flist = NULL;  /* Pointer to the top of      */
                                                              /* the 'pkt_desc_list' free list.    */
static struct pkt_desc_list_elem *last_pkt_desc_flist = NULL; /* Pointer to the last used   */
                                                              /* element list.  */

/* Alloc a new space for an element in pkt_desc_list */
pkt_desc_t *pkt_desc_alloc()
{
  pkt_desc_t *new_pkt_desc_ptr;
#ifdef MEMDEBUG
  IN_USE_PKT_DESC++;
#endif

  if ((last_pkt_desc_flist == NULL) || (last_pkt_desc_flist->pkt_desc_ptr == NULL))
  { /* The LinkList stack is empty.         */
    new_pkt_desc_ptr = (pkt_desc_t *)MMmalloc(sizeof(pkt_desc_t), "pkt_desc_alloc");
#ifdef MEMDEBUG
    TOT_PKT_DESC++;
#endif
    return new_pkt_desc_ptr;
  }
  else
  { /* The 'pkt_desc_list' stack is not empty.   */
    new_pkt_desc_ptr = last_pkt_desc_flist->pkt_desc_ptr;
    last_pkt_desc_flist->pkt_desc_ptr = NULL;
    if (last_pkt_desc_flist->next != NULL)
      last_pkt_desc_flist = last_pkt_desc_flist->next;
    return new_pkt_desc_ptr;
  }
}

void pkt_desc_release(pkt_desc_t *rel_pkt_desc_ptr)
{
  struct pkt_desc_list_elem *new_pkt_desc_list_elem;
#ifdef MEMDEBUG
  IN_USE_PKT_DESC--;
#endif

  memset(rel_pkt_desc_ptr, 0, sizeof(pkt_desc_t));

  if ((last_pkt_desc_flist == NULL) || ((last_pkt_desc_flist->pkt_desc_ptr != NULL) && (last_pkt_desc_flist->prev == NULL)))
  {
    new_pkt_desc_list_elem = (struct pkt_desc_list_elem *)MMmalloc(sizeof(struct pkt_desc_list_elem), "pkt_desc_release");
    new_pkt_desc_list_elem->pkt_desc_ptr = rel_pkt_desc_ptr;
    new_pkt_desc_list_elem->prev = NULL;
    new_pkt_desc_list_elem->next = top_pkt_desc_flist;
    if (new_pkt_desc_list_elem->next != NULL)
      new_pkt_desc_list_elem->next->prev = new_pkt_desc_list_elem;
    top_pkt_desc_flist = new_pkt_desc_list_elem;
    last_pkt_desc_flist = new_pkt_desc_list_elem;
  }
  else
  {
    if (last_pkt_desc_flist->pkt_desc_ptr == NULL)
      new_pkt_desc_list_elem = last_pkt_desc_flist;
    else
      new_pkt_desc_list_elem = last_pkt_desc_flist->prev;
    new_pkt_desc_list_elem->pkt_desc_ptr = rel_pkt_desc_ptr;
    last_pkt_desc_flist = new_pkt_desc_list_elem;
  }
}

/* Garbage collector for Flow Hash Table */
static flow_hash *top_flow_hash_flist = NULL; /* Pointer to the top of      */
                                              /* the 'flow_hash' free list.    */

/* Alloc a new space for entry in flow hash table */
flow_hash *flow_hash_alloc()
{
  struct flow_hash *new_flow_hash_ptr;

#ifdef MEMDEBUG
  IN_USE_FLOW_HASH++;
#endif

  if (top_flow_hash_flist == NULL)
  {
    new_flow_hash_ptr = (flow_hash *)MMmalloc(sizeof(flow_hash), "flow_hash_alloc");
#ifdef MEMDEBUG
    TOT_FLOW_HASH++;
#endif
  }
  else
  {
    new_flow_hash_ptr = top_flow_hash_flist;
    top_flow_hash_flist = top_flow_hash_flist->next;
  }
  new_flow_hash_ptr->next = NULL;
  return (new_flow_hash_ptr);
}

void flow_hash_release(flow_hash *rel_flow_hash_ptr)
{
#ifdef MEMDEBUG
  IN_USE_FLOW_HASH--;
#endif
  memset(rel_flow_hash_ptr, 0, sizeof(flow_hash));
  rel_flow_hash_ptr->next = top_flow_hash_flist;
  top_flow_hash_flist = rel_flow_hash_ptr;
}

/* Circular Buffer Operations */
/* Reference: https://github.com/embeddedartistry/embedded-resources/tree/master/examples/c/circular_buffer */
static inline size_t advance_headtail_value(size_t value, size_t max)
{
  if (++value == max)
  {
    value = 0;
  }
  return value;
}

circular_buf_t *circular_buf_init(pkt_desc_t **pkt_desc_buf, size_t size)
{
  assert(pkt_desc_buf && size > 1);

  circular_buf_t *cbuf = malloc(sizeof(circular_buf_t));
  assert(cbuf);

  cbuf->pkt_desc_buf = pkt_desc_buf;
  cbuf->max = size;
  circular_buf_reset(cbuf);

  assert(circular_buf_empty(cbuf));

  return cbuf;
}

void circular_buf_reset(circular_buf_t *me)
{
  assert(me);

  me->tail = 0;
  me->head = 0;
}

void circular_buf_free(circular_buf_t *me)
{
  assert(me);
  free(me);
}

Bool circular_buf_full(circular_buf_t *me)
{
  // We want to check, not advance, so we don't save the output here
  return advance_headtail_value(me->tail, me->max) == me->head;
}

Bool circular_buf_empty(circular_buf_t *me)
{
  assert(me);
  return (me->tail == me->head);
}

size_t circular_buf_capacity(circular_buf_t *me)
{
  assert(me);

  // We account for the space we can't use for thread safety
  return me->max - 1;
}

size_t circular_buf_size(circular_buf_t *me)
{
  assert(me);

  // We account for the space we can't use for thread safety
  size_t size = me->max - 1;

  if (!circular_buf_full(me))
  {
    if (me->tail >= me->head)
    {
      size = (me->tail - me->head);
    }
    else
    {
      size = (me->max + me->tail - me->head);
    }
  }

  return size;
}

/// For thread safety, do not use put - use try_put.
/// Because this version, which will overwrite the existing contents
/// of the buffer, will involve modifying the tail pointer, which is also
/// modified by get.
struct pkt_desc_t **circular_buf_try_put(circular_buf_t *me, struct pkt_desc_t *pkt_desc_ptr)
{
  assert(me && me->pkt_desc_buf);
  struct pkt_desc_t **temp_pkt_desc_ptr_ptr;
  if (!circular_buf_full(me))
  {
    me->pkt_desc_buf[me->tail] = pkt_desc_ptr;
    temp_pkt_desc_ptr_ptr = &(me->pkt_desc_buf[me->tail]);
    me->tail = advance_headtail_value(me->tail, me->max);
    return temp_pkt_desc_ptr_ptr;
  }
  else
  {
    return NULL;
  }
}

/*To remove data from the buffer, we access the value at the tail and then update the tail pointer.
 * If the buffer is empty we do not return a value or modify the pointer.
 * Instead, we return an error to the user. */
int circular_buf_get(circular_buf_t *me, struct pkt_desc_t **pkt_desc_ptr_ptr)
{
  int r = -1;

  if (me && !circular_buf_empty(me))
  {
    *pkt_desc_ptr_ptr = me->pkt_desc_buf[me->head];
    me->head = advance_headtail_value(me->head, me->max);
    r = 0;
  }

  return r;
}

/* To check the elements pointed by the tail without advancing the tail. */
int circular_buf_peek_one(circular_buf_t* me, struct pkt_desc_t **pkt_desc_ptr_ptr)
{
  int r = -1;

  // /* advance the tail until there is a valid value */
  // while (me->pkt_desc_buf[me->head] == NULL)
  // {
  //   me->head = advance_headtail_value(me->head, me->max);
  //   printf("asssss\n");
  // }
  
  if (me && !circular_buf_empty(me))
  {
    *pkt_desc_ptr_ptr = me->pkt_desc_buf[me->head];
    r = 0;
  }

  return r;
}