#ifndef _LINUX_RCULIST_H
#define _LINUX_RCULIST_H

#include <linux/list.h>
#include <onyx/rculist.h>

/**
 * list_next_or_null_rcu - get the next element from a list
 * @head:	the head for the list.
 * @ptr:        the list head to take the next element from.
 * @type:       the type of the struct this is embedded in.
 * @member:     the name of the list_head within the struct.
 *
 * Note that if the ptr is at the end of the list, NULL is returned.
 *
 * This primitive may safely run concurrently with the _rcu list-mutation
 * primitives such as list_add_rcu() as long as it's guarded by rcu_read_lock().
 */
#define list_next_or_null_rcu(head, ptr, type, member) \
({ \
	struct list_head *__head = (head); \
	struct list_head *__ptr = (ptr); \
	struct list_head *__next = READ_ONCE(__ptr->next); \
	likely(__next != __head) ? list_entry_rcu(__next, type, \
						  member) : NULL; \
})

#define list_del_rcu(entry) list_remove_rcu(entry)

#define __list_check_rcu(...) ({})

/*
 * return the first or the next element in an RCU protected hlist
 */
#define hlist_first_rcu(head)	(*((struct hlist_node __rcu **)(&(head)->first)))
#define hlist_next_rcu(node)	(*((struct hlist_node __rcu **)(&(node)->next)))
#define hlist_pprev_rcu(node)	(*((struct hlist_node __rcu **)((node)->pprev)))

/**
 * hlist_add_head_rcu
 * @n: the element to add to the hash list.
 * @h: the list to add to.
 *
 * Description:
 * Adds the specified element to the specified hlist,
 * while permitting racing traversals.
 *
 * The caller must take whatever precautions are necessary
 * (such as holding appropriate locks) to avoid racing
 * with another list-mutation primitive, such as hlist_add_head_rcu()
 * or hlist_del_rcu(), running on this same list.
 * However, it is perfectly legal to run concurrently with
 * the _rcu list-traversal primitives, such as
 * hlist_for_each_entry_rcu(), used to prevent memory-consistency
 * problems on Alpha CPUs.  Regardless of the type of CPU, the
 * list-traversal primitive must be guarded by rcu_read_lock().
 */
static inline void hlist_add_head_rcu(struct hlist_node *n,
					struct hlist_head *h)
{
	struct hlist_node *first = h->first;

	n->next = first;
	WRITE_ONCE(n->pprev, &h->first);
	rcu_assign_pointer(hlist_first_rcu(h), n);
	if (first)
		WRITE_ONCE(first->pprev, &n->next);
}

/**
 * hlist_add_tail_rcu
 * @n: the element to add to the hash list.
 * @h: the list to add to.
 *
 * Description:
 * Adds the specified element to the specified hlist,
 * while permitting racing traversals.
 *
 * The caller must take whatever precautions are necessary
 * (such as holding appropriate locks) to avoid racing
 * with another list-mutation primitive, such as hlist_add_head_rcu()
 * or hlist_del_rcu(), running on this same list.
 * However, it is perfectly legal to run concurrently with
 * the _rcu list-traversal primitives, such as
 * hlist_for_each_entry_rcu(), used to prevent memory-consistency
 * problems on Alpha CPUs.  Regardless of the type of CPU, the
 * list-traversal primitive must be guarded by rcu_read_lock().
 */
static inline void hlist_add_tail_rcu(struct hlist_node *n,
				      struct hlist_head *h)
{
	struct hlist_node *i, *last = NULL;

	/* Note: write side code, so rcu accessors are not needed. */
	for (i = h->first; i; i = i->next)
		last = i;

	if (last) {
		n->next = last->next;
		WRITE_ONCE(n->pprev, &last->next);
		rcu_assign_pointer(hlist_next_rcu(last), n);
	} else {
		hlist_add_head_rcu(n, h);
	}
}

/**
 * hlist_add_before_rcu
 * @n: the new element to add to the hash list.
 * @next: the existing element to add the new element before.
 *
 * Description:
 * Adds the specified element to the specified hlist
 * before the specified node while permitting racing traversals.
 *
 * The caller must take whatever precautions are necessary
 * (such as holding appropriate locks) to avoid racing
 * with another list-mutation primitive, such as hlist_add_head_rcu()
 * or hlist_del_rcu(), running on this same list.
 * However, it is perfectly legal to run concurrently with
 * the _rcu list-traversal primitives, such as
 * hlist_for_each_entry_rcu(), used to prevent memory-consistency
 * problems on Alpha CPUs.
 */
static inline void hlist_add_before_rcu(struct hlist_node *n,
					struct hlist_node *next)
{
	WRITE_ONCE(n->pprev, next->pprev);
	n->next = next;
	rcu_assign_pointer(hlist_pprev_rcu(n), n);
	WRITE_ONCE(next->pprev, &n->next);
}

/**
 * hlist_add_behind_rcu
 * @n: the new element to add to the hash list.
 * @prev: the existing element to add the new element after.
 *
 * Description:
 * Adds the specified element to the specified hlist
 * after the specified node while permitting racing traversals.
 *
 * The caller must take whatever precautions are necessary
 * (such as holding appropriate locks) to avoid racing
 * with another list-mutation primitive, such as hlist_add_head_rcu()
 * or hlist_del_rcu(), running on this same list.
 * However, it is perfectly legal to run concurrently with
 * the _rcu list-traversal primitives, such as
 * hlist_for_each_entry_rcu(), used to prevent memory-consistency
 * problems on Alpha CPUs.
 */
static inline void hlist_add_behind_rcu(struct hlist_node *n,
					struct hlist_node *prev)
{
	n->next = prev->next;
	WRITE_ONCE(n->pprev, &prev->next);
	rcu_assign_pointer(hlist_next_rcu(prev), n);
	if (n->next)
		WRITE_ONCE(n->next->pprev, &n->next);
}

#define __hlist_for_each_rcu(pos, head)				\
	for (pos = rcu_dereference(hlist_first_rcu(head));	\
	     pos;						\
	     pos = rcu_dereference(hlist_next_rcu(pos)))

#define hlist_for_each_entry_rcu_notrace(pos, head, member)			\
	for (pos = hlist_entry_safe(rcu_dereference_raw_check(hlist_first_rcu(head)),\
			typeof(*(pos)), member);			\
		pos;							\
		pos = hlist_entry_safe(rcu_dereference_raw_check(hlist_next_rcu(\
			&(pos)->member)), typeof(*(pos)), member))

/**
 * hlist_for_each_entry_rcu_bh - iterate over rcu list of given type
 * @pos:	the type * to use as a loop cursor.
 * @head:	the head for your list.
 * @member:	the name of the hlist_node within the struct.
 *
 * This list-traversal primitive may safely run concurrently with
 * the _rcu list-mutation primitives such as hlist_add_head_rcu()
 * as long as the traversal is guarded by rcu_read_lock().
 */
#define hlist_for_each_entry_rcu_bh(pos, head, member)			\
	for (pos = hlist_entry_safe(rcu_dereference_bh(hlist_first_rcu(head)),\
			typeof(*(pos)), member);			\
		pos;							\
		pos = hlist_entry_safe(rcu_dereference_bh(hlist_next_rcu(\
			&(pos)->member)), typeof(*(pos)), member))

/**
 * hlist_for_each_entry_continue_rcu - iterate over a hlist continuing after current point
 * @pos:	the type * to use as a loop cursor.
 * @member:	the name of the hlist_node within the struct.
 */
#define hlist_for_each_entry_continue_rcu(pos, member)			\
	for (pos = hlist_entry_safe(rcu_dereference_raw(hlist_next_rcu( \
			&(pos)->member)), typeof(*(pos)), member);	\
	     pos;							\
	     pos = hlist_entry_safe(rcu_dereference_raw(hlist_next_rcu(	\
			&(pos)->member)), typeof(*(pos)), member))

/**
 * hlist_for_each_entry_continue_rcu_bh - iterate over a hlist continuing after current point
 * @pos:	the type * to use as a loop cursor.
 * @member:	the name of the hlist_node within the struct.
 */
#define hlist_for_each_entry_continue_rcu_bh(pos, member)		\
	for (pos = hlist_entry_safe(rcu_dereference_bh(hlist_next_rcu(  \
			&(pos)->member)), typeof(*(pos)), member);	\
	     pos;							\
	     pos = hlist_entry_safe(rcu_dereference_bh(hlist_next_rcu(	\
			&(pos)->member)), typeof(*(pos)), member))

/**
 * hlist_for_each_entry_from_rcu - iterate over a hlist continuing from current point
 * @pos:	the type * to use as a loop cursor.
 * @member:	the name of the hlist_node within the struct.
 */
#define hlist_for_each_entry_from_rcu(pos, member)			\
	for (; pos;							\
	     pos = hlist_entry_safe(rcu_dereference_raw(hlist_next_rcu(	\
			&(pos)->member)), typeof(*(pos)), member))

/**
 * hlist_for_each_entry_rcu - iterate over rcu list of given type
 * @pos:	the type * to use as a loop cursor.
 * @head:	the head for your list.
 * @member:	the name of the hlist_node within the struct.
 * @cond:	optional lockdep expression if called from non-RCU protection.
 *
 * This list-traversal primitive may safely run concurrently with
 * the _rcu list-mutation primitives such as hlist_add_head_rcu()
 * as long as the traversal is guarded by rcu_read_lock().
 */
#define hlist_for_each_entry_rcu(pos, head, member, cond...)		\
	for (__list_check_rcu(dummy, ## cond, 0),			\
	     pos = hlist_entry_safe(rcu_dereference_raw(hlist_first_rcu(head)),\
			typeof(*(pos)), member);			\
		pos;							\
		pos = hlist_entry_safe(rcu_dereference_raw(hlist_next_rcu(\
			&(pos)->member)), typeof(*(pos)), member))

/**
 * hlist_del_rcu - deletes entry from hash list without re-initialization
 * @n: the element to delete from the hash list.
 *
 * Note: list_unhashed() on entry does not return true after this,
 * the entry is in an undefined state. It is useful for RCU based
 * lockfree traversal.
 *
 * In particular, it means that we can not poison the forward
 * pointers that may still be used for walking the hash list.
 *
 * The caller must take whatever precautions are necessary
 * (such as holding appropriate locks) to avoid racing
 * with another list-mutation primitive, such as hlist_add_head_rcu()
 * or hlist_del_rcu(), running on this same list.
 * However, it is perfectly legal to run concurrently with
 * the _rcu list-traversal primitives, such as
 * hlist_for_each_entry().
 */
static inline void hlist_del_rcu(struct hlist_node *n)
{
	__hlist_del(n);
	WRITE_ONCE(n->pprev, LIST_POISON2);
}

#endif
