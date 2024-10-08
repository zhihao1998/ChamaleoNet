#include "tsdn.h"

/*
** Memory management with freelist instead of malloc and free.
**
*/
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
            "\nError:  Memory allocation error in %s\n", f_name);
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
#ifdef DO_STATS
  pkt_list_count_use++;
#endif

  if ((last_pkt_flist == NULL) || (last_pkt_flist->ppkt == NULL))
  { /* The LinkList stack is empty.         */
    /* fprintf (fp_stdout, "FList empty, top == last == NULL\n"); */
    ppkt_temp = (ip_packet *)MMmalloc(sizeof(ip_packet), "pkt_alloc");
#ifdef DO_STATS
    pkt_list_count_tot++;
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

#ifdef DO_STATS
  pkt_list_count_use--;
#endif

  memset(released_ip_packet, 0, sizeof(ip_packet));

  if ((last_pkt_flist == NULL) || ((last_pkt_flist->ppkt != NULL) && (last_pkt_flist->prev == NULL)))
  {
    new_pktlist_elem =
        (struct pkt_list_elem *)MMmalloc(sizeof(struct pkt_list_elem),
                                         "pkt_release");
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

void pkt_list_print()
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

/* Garbage collector for Flow Hash Table */
static flow_hash_t *top_flow_hash_flist = NULL; /* Pointer to the top of      */
                                                /* the 'flow_hash' free list.    */

/* Alloc a new space for entry in flow hash table */
flow_hash_t *flow_hash_alloc()
{
  struct flow_hash_t *new_flow_hash_ptr;

#ifdef DO_STATS
  flow_hash_list_count_use++;
#endif

  if (top_flow_hash_flist == NULL)
  {
    new_flow_hash_ptr = (flow_hash_t *)MMmalloc(sizeof(flow_hash_t), "flow_hash_alloc");
#ifdef DO_STATS
    flow_hash_list_count_tot++;
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

void flow_hash_release(flow_hash_t *rel_flow_hash_ptr)
{
#ifdef DO_STATS
  flow_hash_list_count_use--;
#endif
  memset(rel_flow_hash_ptr, 0, sizeof(flow_hash_t));
  rel_flow_hash_ptr->next = top_flow_hash_flist;
  top_flow_hash_flist = rel_flow_hash_ptr;
}

/* Garbage collector for Service Hash Table */
static service_hash_t *top_service_hash_flist = NULL; /* Pointer to the top of      */
                                                /* the 'flow_hash' free list.    */

/* Alloc a new space for entry in flow hash table */
service_hash_t *service_hash_alloc()
{
  struct service_hash_t *new_service_hash_ptr;

#ifdef DO_STATS
  service_hash_list_count_use++;
#endif

  if (top_service_hash_flist == NULL)
  {
    new_service_hash_ptr = (service_hash_t *)MMmalloc(sizeof(service_hash_t), "service_hash_alloc");
#ifdef DO_STATS
    service_hash_list_count_tot++;
#endif
  }
  else
  {
    new_service_hash_ptr = top_service_hash_flist;
    top_service_hash_flist = top_service_hash_flist->next;
  }
  new_service_hash_ptr->next = NULL;
  return (new_service_hash_ptr);
}

void service_hash_release(service_hash_t *rel_service_hash_ptr)
{
#ifdef DO_STATS
  service_hash_list_count_use--;
#endif
  memset(rel_service_hash_ptr, 0, sizeof(service_hash_t));
  rel_service_hash_ptr->next = top_service_hash_flist;
  top_service_hash_flist = rel_service_hash_ptr;
}

/* Circular Buffer Operations */
/* Reference: https://github.com/embeddedartistry/embedded-resources/tree/master/examples/c/circular_buffer */
static inline size_t advance_headtail_value(size_t value, size_t max)
{
  return (value + 1) % max;
}

circular_buf_t *circular_buf_init(void **buf_space, size_t size)
{
  assert(buf_space && size > 1);

  circular_buf_t *cbuf = malloc(sizeof(circular_buf_t));
  assert(cbuf);

  cbuf->buf_space = buf_space;
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
  assert(me);
  return ((me->head == me->tail) && (me->head != 0)) || (me->tail == me->max);
}

Bool circular_buf_empty(circular_buf_t *me)
{
  assert(me);
  return ((me->head == me->tail) && (me->head == 0));
}

size_t circular_buf_capacity(circular_buf_t *me)
{
  assert(me);

  return me->max;
}

size_t circular_buf_size(circular_buf_t *me)
{
  assert(me);

  size_t size = me->max;

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

void **circular_buf_try_put(circular_buf_t *me, void *buf_slot_ptr)
{
  assert(me && me->buf_space);
  void **temp_buf_slot_ptr_ptr;
  if (!circular_buf_full(me))
  {
    me->buf_space[me->tail] = buf_slot_ptr;
    temp_buf_slot_ptr_ptr = &(me->buf_space[me->tail]);
    me->tail = advance_headtail_value(me->tail, me->max);
    if (me->tail == me->max)
    {
      me->tail = 0;
    }
    return temp_buf_slot_ptr_ptr;
  }
  else
  {
    return NULL;
  }
}

/*To remove data from the buffer, we access the value at the tail and then update the tail pointer.
 * If the buffer is empty we do not return a value or modify the pointer.
 * Instead, we return an error to the user. */
int circular_buf_get(circular_buf_t *me, void **buf_slot_ptr_ptr)
{
  int r = -1;
  assert(me && me->buf_space);

  if (!circular_buf_empty(me))
  {
    *buf_slot_ptr_ptr = me->buf_space[me->head];
    if (me->tail == me->max)
    {
      me->tail = 0;
    }
    me->head = advance_headtail_value(me->head, me->max);
    if (me->head == me->tail)
    {
      me->tail = 0;
      me->head = 0;
    }
    r = 0;
  }

  return r;
}

/* peek head */
int circular_buf_peek_head(circular_buf_t *me, void **buf_slot_ptr_ptr)
{
  int r = -1;

  if (me && !circular_buf_empty(me))
  {
    *buf_slot_ptr_ptr = me->buf_space[me->head];
    r = 0;
  }

  return r;
}

void *
MallocZ(int nbytes)
{
  char *ptr;

  // ptr = malloc(nbytes);
  ptr = calloc(1, nbytes);
  if (ptr == NULL)
  {
    fprintf(fp_stderr, "Malloc failed, fatal: %s\n", strerror(errno));
    fprintf(fp_stderr,
            "when memory allocation fails, it's either because:\n"
            "1) You're out of swap space, talk to your local "
            "sysadmin about making more\n"
            "(look for system commands 'swap' or 'swapon' for quick fixes)\n"
            "2) The amount of memory that your OS gives each process "
            "is too little\n"
            "That's a system configuration issue that you'll need to discuss\n"
            "with the system administrator\n");
    exit(EXIT_FAILURE);
  }

  // memset(ptr, 0, nbytes); /* BZERO */
  return (ptr);
}

/* Garbage collector for Table Entry Array
 *  Two pointer are used (top and last).
 *  Alloc and release from last, while top is used to not loose the list ...
 */

static struct table_entry_list_elem *top_table_entry_flist = NULL;  /* Pointer to the top of      */
                                                              /* the 'table_entry_list' free list.    */
static struct table_entry_list_elem *last_table_entry_flist = NULL; /* Pointer to the last used   */
                                                              /* element list.  */

/* Alloc a new space for an element in table_entry_list */
table_entry_t *table_entry_alloc()
{
  table_entry_t *new_table_entry_ptr;

  if ((last_table_entry_flist == NULL) || (last_table_entry_flist->table_entry_ptr == NULL))
  { /* The LinkList stack is empty.         */
    new_table_entry_ptr = (table_entry_t *)MMmalloc(sizeof(table_entry_t), "table_entry_alloc");
    return new_table_entry_ptr;
  }
  else
  { /* The 'table_entry_list' stack is not empty.   */
    new_table_entry_ptr = last_table_entry_flist->table_entry_ptr;
    last_table_entry_flist->table_entry_ptr = NULL;
    if (last_table_entry_flist->next != NULL)
      last_table_entry_flist = last_table_entry_flist->next;
    return new_table_entry_ptr;
  }
}

void table_entry_release(table_entry_t *rel_table_entry_ptr)
{
  struct table_entry_list_elem *new_table_entry_list_elem;

  memset(rel_table_entry_ptr, 0, sizeof(table_entry_t));

  if ((last_table_entry_flist == NULL) || ((last_table_entry_flist->table_entry_ptr != NULL) && (last_table_entry_flist->prev == NULL)))
  {
    new_table_entry_list_elem = (struct table_entry_list_elem *)MMmalloc(sizeof(struct table_entry_list_elem), "table_entry_release");
    new_table_entry_list_elem->table_entry_ptr = rel_table_entry_ptr;
    new_table_entry_list_elem->prev = NULL;
    new_table_entry_list_elem->next = top_table_entry_flist;
    if (new_table_entry_list_elem->next != NULL)
      new_table_entry_list_elem->next->prev = new_table_entry_list_elem;
    top_table_entry_flist = new_table_entry_list_elem;
    last_table_entry_flist = new_table_entry_list_elem;
  }
  else
  {
    if (last_table_entry_flist->table_entry_ptr == NULL)
      new_table_entry_list_elem = last_table_entry_flist;
    else
      new_table_entry_list_elem = last_table_entry_flist->prev;
    new_table_entry_list_elem->table_entry_ptr = rel_table_entry_ptr;
    last_table_entry_flist = new_table_entry_list_elem;
  }
}
