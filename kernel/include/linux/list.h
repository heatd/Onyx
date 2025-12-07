#ifndef _LINUX_LIST_H
#define _LINUX_LIST_H

#include <onyx/list.h>

static bool list_empty(const struct list_head *l)
{
    return list_is_empty(l);
}

#define LIST_HEAD(name) DEFINE_LIST(name)

#define list_first_entry_or_null(lh, type, memb) \
    (list_empty(lh) ? NULL : container_of(list_first_element(lh), type, memb))

/**
 * list_prev_entry - get the prev element in list
 * @pos:	the type * to cursor
 * @member:	the name of the list_head within the struct.
 */
#define list_prev_entry(pos, member) \
	list_entry((pos)->member.prev, typeof(*(pos)), member)

/**
 * list_last_entry_or_null - get the last element from a list
 * @ptr:	the list head to take the element from.
 * @type:	the type of the struct this is embedded in.
 * @member:	the name of the list_head within the struct.
 *
 * Note that if the list is empty, it returns NULL.
 */
#define list_last_entry_or_null(ptr, type, member) ({ \
	struct list_head *head__ = (ptr); \
	struct list_head *pos__ = READ_ONCE(head__->prev); \
	pos__ != head__ ? list_entry(pos__, type, member) : NULL; \
})

/**
 * list_for_each_entry_from - iterate over list of given type from the current point
 * @pos:	the type * to use as a loop cursor.
 * @head:	the head for your list.
 * @member:	the name of the list_head within the struct.
 *
 * Iterate over list of given type, continuing from current position.
 */
#define list_for_each_entry_from(pos, head, member) 			\
	for (; !list_entry_is_head(pos, head, member);			\
	     pos = list_next_entry(pos, member))

/**
 * list_for_each_entry_from_reverse - iterate backwards over list of given type
 *                                    from the current point
 * @pos:	the type * to use as a loop cursor.
 * @head:	the head for your list.
 * @member:	the name of the list_head within the struct.
 *
 * Iterate backwards over list of given type, continuing from current position.
 */
#define list_for_each_entry_from_reverse(pos, head, member)		\
	for (; !list_entry_is_head(pos, head, member);			\
	     pos = list_prev_entry(pos, member))

/**
 * list_for_each_entry_reverse - iterate backwards over list of given type.
 * @pos:	the type * to use as a loop cursor.
 * @head:	the head for your list.
 * @member:	the name of the list_head within the struct.
 */
#define list_for_each_entry_reverse(pos, head, member)			\
	for (pos = list_last_entry(head, typeof(*pos), member);		\
	     !list_entry_is_head(pos, head, member); 			\
	     pos = list_prev_entry(pos, member))


static inline void __list_del_entry(struct list_head *entry)
{
    list_remove_bulk(entry->prev, entry->next);
}

static inline void list_del(struct list_head *l)
{
    list_remove(l);
}

static inline void list_del_init(struct list_head *l)
{
    list_remove(l);
    INIT_LIST_HEAD(l);
}

/* TODO: list_move in onyx/list.h is an awful footgun */
static inline void list_move_tail(struct list_head *l, struct list_head *dest)
{
    list_remove(l);
    list_add_tail(l, dest);
}

static inline void list_splice_init(struct list_head *l, struct list_head *head)
{
    list_splice(l, head);
    INIT_LIST_HEAD(l);
}

static inline bool list_is_last(struct list_head *l, struct list_head *head)
{
    return head->prev == l;
}

static inline bool list_is_first(struct list_head *l, struct list_head *head)
{
    return head->next == l;
}


#include <linux/hlist.h>

#endif
