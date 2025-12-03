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

static inline void list_del(struct list_head *l)
{
    list_remove(l);
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

#include <linux/hlist.h>

#endif
