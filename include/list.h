#ifndef __QNSM_LIST_H
#define __QNSM_LIST_H

/* This file is from Linux Kernel (include/linux/list.h)
 * and modified by simply removing hardware prefetching of list items.
 * Here by copyright, credits attributed to wherever they belong.
 * Kulesh Shanmugasundaram (kulesh [squiggly] isis.poly.edu)
 */

/*
 * Simple doubly linked list implementation.
 *
 * Some of the internal functions ("__xxx") are useful when
 * manipulating whole lists rather than single entries, as
 * sometimes we already know the next/prev entries and we can
 * generate better code by using them directly rather than
 * using the generic single-entry routines.
 */

struct qnsm_list_head {
    struct qnsm_list_head *next, *prev;
};

#define QNSM_LIST_HEAD_INIT(name) { &(name), &(name) }

#define QNSM_LIST_HEAD(name) \
    struct qnsm_list_head name = QNSM_LIST_HEAD_INIT(name)

#define QNSM_INIT_LIST_HEAD(ptr) do { \
    (ptr)->next = (ptr); (ptr)->prev = (ptr); \
} while (0)

/*
 * Insert a new entry between two known consecutive entries.
 *
 * This is only for internal list manipulation where we know
 * the prev/next entries already!
 */
static inline void __qnsm_list_add(struct qnsm_list_head *new,
                                   struct qnsm_list_head *prev,
                                   struct qnsm_list_head *next)
{
    next->prev = new;
    new->next = next;
    new->prev = prev;
    prev->next = new;
}

/**
 * list_add - add a new entry
 * @new: new entry to be added
 * @head: list head to add it after
 *
 * Insert a new entry after the specified head.
 * This is good for implementing stacks.
 */
static inline void qnsm_list_add(struct qnsm_list_head *new, struct qnsm_list_head *head)
{
    __qnsm_list_add(new, head, head->next);
}

/**
 * list_add_tail - add a new entry
 * @new: new entry to be added
 * @head: list head to add it before
 *
 * Insert a new entry before the specified head.
 * This is useful for implementing queues.
 */
static inline void qnsm_list_add_tail(struct qnsm_list_head *new, struct qnsm_list_head *head)
{
    __qnsm_list_add(new, head->prev, head);
}

#define QNSM_LIST_ADD_BEFORE(new, node) qnsm_list_add_tail(new, node)
#define QNSM_LIST_ADD_AFTER(new, node) qnsm_list_add(new, node)


/*
 * Delete a list entry by making the prev/next entries
 * point to each other.
 *
 * This is only for internal list manipulation where we know
 * the prev/next entries already!
 */
static inline void __qnsm_list_del(struct qnsm_list_head *prev, struct qnsm_list_head *next)
{
    next->prev = prev;
    prev->next = next;
}

/**
 * list_del - deletes entry from list.
 * @entry: the element to delete from the list.
 * Note: list_empty on entry does not return true after this, the entry is in an undefined state.
 */
static inline void qnsm_list_del(struct qnsm_list_head *entry)
{
    __qnsm_list_del(entry->prev, entry->next);
    entry->next = (void *) 0;
    entry->prev = (void *) 0;
}

/**
 * list_del_init - deletes entry from list and reinitialize it.
 * @entry: the element to delete from the list.
 */
static inline void qnsm_list_del_init(struct qnsm_list_head *entry)
{
    __qnsm_list_del(entry->prev, entry->next);
    QNSM_INIT_LIST_HEAD(entry);
}

/**
 * list_move - delete from one list and add as another's head
 * @list: the entry to move
 * @head: the head that will precede our entry
 */
static inline void qnsm_list_move(struct qnsm_list_head *list, struct qnsm_list_head *head)
{
    __qnsm_list_del(list->prev, list->next);
    qnsm_list_add(list, head);
}

/**
 * list_move_tail - delete from one list and add as another's tail
 * @list: the entry to move
 * @head: the head that will follow our entry
 */
static inline void qnsm_list_move_tail(struct qnsm_list_head *list,
                                       struct qnsm_list_head *head)
{
    __qnsm_list_del(list->prev, list->next);
    qnsm_list_add_tail(list, head);
}

/**
 * list_empty - tests whether a list is empty
 * @head: the list to test.
 */
static inline int qnsm_list_empty(struct qnsm_list_head *head)
{
    return head->next == head;
}

static inline void __qnsm_list_splice(struct qnsm_list_head *list,
                                      struct qnsm_list_head *head)
{
    struct qnsm_list_head *first = list->next;
    struct qnsm_list_head *last = list->prev;
    struct qnsm_list_head *at = head->next;

    first->prev = head;
    head->next = first;

    last->next = at;
    at->prev = last;
}

/**
 * list_splice - join two lists
 * @list: the new list to add.
 * @head: the place to add it in the first list.
 */
static inline void qnsm_list_splice(struct qnsm_list_head *list, struct qnsm_list_head *head)
{
    if (!qnsm_list_empty(list))
        __qnsm_list_splice(list, head);
}

/**
 * list_splice_init - join two lists and reinitialise the emptied list.
 * @list: the new list to add.
 * @head: the place to add it in the first list.
 *
 * The list at @list is reinitialised
 */
static inline void qnsm_list_splice_init(struct qnsm_list_head *list,
        struct qnsm_list_head *head)
{
    if (!qnsm_list_empty(list)) {
        __qnsm_list_splice(list, head);
        QNSM_INIT_LIST_HEAD(list);
    }
}

/**
 * list_entry - get the struct for this entry
 * @ptr:    the &struct list_head pointer.
 * @type:   the type of the struct this is embedded in.
 * @member: the name of the list_struct within the struct.
 */
#define qnsm_list_entry(ptr, type, member) \
    ((type *)((char *)(ptr)-(unsigned long)(&((type *)0)->member)))

/**
 * list_for_each    -   iterate over a list
 * @pos:    the &struct list_head to use as a loop counter.
 * @head:   the head for your list.
 */
#define qnsm_list_for_each(pos, head) \
    for (pos = (head)->next; pos != (head); \
            pos = pos->next)
/**
 * list_for_each_prev   -   iterate over a list backwards
 * @pos:    the &struct list_head to use as a loop counter.
 * @head:   the head for your list.
 */
#define qnsm_list_for_each_prev(pos, head) \
    for (pos = (head)->prev; pos != (head); \
            pos = pos->prev)

#define qnsm_list_for_each_prev_entry(pos, head, member) \
    for (pos = qnsm_list_entry((head)->prev, typeof(*pos), member); \
         &pos->member != (head); \
            pos = qnsm_list_entry(pos->member.prev, typeof(*pos), member))

/**
 * list_for_each_safe   -   iterate over a list safe against removal of list entry
 * @pos:    the &struct list_head to use as a loop counter.
 * @n:      another &struct list_head to use as temporary storage
 * @head:   the head for your list.
 */
#define qnsm_list_for_each_safe(pos, n, head) \
    for (pos = (head)->next, n = pos->next; pos != (head); \
        pos = n, n = pos->next)

/**
 * list_for_each_entry  -   iterate over list of given type
 * @pos:    the type * to use as a loop counter.
 * @head:   the head for your list.
 * @member: the name of the list_struct within the struct.
 */
#define qnsm_list_for_each_entry(pos, head, member)             \
    for (pos = qnsm_list_entry((head)->next, typeof(*pos), member); \
         &pos->member != (head);                    \
         pos = qnsm_list_entry(pos->member.next, typeof(*pos), member))

/**
 * list_for_each_entry_safe - iterate over list of given type safe against removal of list entry
 * @pos:    the type * to use as a loop counter.
 * @n:      another type * to use as temporary storage
 * @head:   the head for your list.
 * @member: the name of the list_struct within the struct.
 */
#define qnsm_list_for_each_entry_safe(pos, n, head, member)         \
    for (pos = qnsm_list_entry((head)->next, typeof(*pos), member), \
        n = qnsm_list_entry(pos->member.next, typeof(*pos), member);    \
         &pos->member != (head);                    \
         pos = n, n = qnsm_list_entry(n->member.next, typeof(*n), member))


/* hlist_* code - double linked lists */
struct hlist_head {
    struct hlist_node *first;
};

struct hlist_node {
    struct hlist_node *next, **pprev;
};

static inline void __hlist_del(struct hlist_node *n)
{
    struct hlist_node *next = n->next;
    struct hlist_node **pprev = n->pprev;
    *pprev = next;
    if (next)
        next->pprev = pprev;
}

static inline void hlist_del(struct hlist_node *n)
{
    __hlist_del(n);
    n->next = NULL;
    n->pprev = NULL;
}

static inline void hlist_add_head(struct hlist_node *n, struct hlist_head *h)
{
    struct hlist_node *first = h->first;
    n->next = first;
    if (first)
        first->pprev = &n->next;
    h->first = n;
    n->pprev = &h->first;
}

static inline int hlist_empty(const struct hlist_head *h)
{
    return !h->first;
}
#define HLIST_HEAD_INIT { .first = NULL }
#define HLIST_HEAD(name) struct hlist_head name = {  .first = NULL }
#define INIT_HLIST_HEAD(ptr) ((ptr)->first = NULL)
static inline void INIT_HLIST_NODE(struct hlist_node *h)
{
    h->next = NULL;
    h->pprev = NULL;
}

#undef container_of
#ifndef offsetof
#define offsetof(type, field)  ((size_t) &( ((type *)0)->field) )
#endif
#define container_of(ptr, type, member) ({ \
        typeof(((type *)0)->member)(*__mptr) = (ptr); \
        (type *)((char *)__mptr - offsetof(type, member)); })

#define hlist_entry(ptr, type, member) container_of(ptr,type,member)

#define hlist_for_each_entry_safe(tpos, pos, n, head, member)            \
        for (pos = (head)->first;                                        \
             pos && ({ n = pos->next; 1; }) &&                           \
            ({ tpos = hlist_entry(pos, typeof(*tpos), member); 1;}); \
             pos = n)


#define hlist_for_each_safe(pos, n, head) \
         for (pos = (head)->first; pos && ({ n = pos->next; 1; }); \
              pos = n)



#endif
