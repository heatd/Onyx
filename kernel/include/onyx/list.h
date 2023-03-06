/*
 * Copyright (c) 2017 - 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef _ONYX_LIST_H
#define _ONYX_LIST_H

#include <stdbool.h>
#include <stdlib.h>

#include <onyx/compiler.h>
#include <onyx/panic.h>
#include <onyx/utils.h>

/* Implementation of struct list_head like linux, so circular */
struct list_head
{
    struct list_head *prev, *next;
};

#ifdef __cplusplus

template <typename T>
class list_head_cpp : public list_head
{
private:
    T *self;

public:
    constexpr list_head_cpp(T *self) : list_head{nullptr, nullptr}, self(self)
    {
        /* *sigh* clang-tidy doesn't shut up about prev and next being uninitialised,
         * so, here we go...
         */
        prev = next = nullptr;
    }
    /* TODO: Do we need to define copy ctors, move ctors here? */

    T *from_list()
    {
        return self;
    }

    static constexpr T *self_from_list_head(struct list_head *lh)
    {
        auto l = static_cast<list_head_cpp *>(lh);
        return l->from_list();
    }

    list_head *to_list_head()
    {
        return this;
    }
};

#endif

#define LIST_HEAD_INIT(lh) \
    {                      \
        &(lh), &(lh)       \
    }

#define DEFINE_LIST(name) struct list_head name = LIST_HEAD_INIT(name);

CONSTEXPR static inline void INIT_LIST_HEAD(struct list_head *lh)
{
    lh->prev = lh;
    lh->next = lh;
}

/* Okay, this was very clearly inspired by linux's list.h but it just links together the
 * new node with rest of the list
 */
static inline void __list_add(struct list_head *_new, struct list_head *prev,
                              struct list_head *next)
{
    next->prev = _new;
    _new->next = next;
    _new->prev = prev;
    prev->next = _new;
}

static inline void list_add(struct list_head *_new, struct list_head *head)
{
    __list_add(_new, head, head->next);
}

static inline void list_add_tail(struct list_head *_new, struct list_head *head)
{
    __list_add(_new, head->prev, head);
}

#define LIST_REMOVE_POISON ((struct list_head *) 0xDEAD)

static inline void list_remove_bulk(struct list_head *prev, struct list_head *next)
{
    prev->next = next;
    next->prev = prev;
}

static inline void list_remove(struct list_head *node)
{
#if DEBUG_LIST
    if (node->prev == LIST_REMOVE_POISON || node->next == LIST_REMOVE_POISON)
        panic("oh no");
#endif
    list_remove_bulk(node->prev, node->next);
    node->prev = node->next = LIST_REMOVE_POISON;
}

static inline bool list_is_empty(const struct list_head *head)
{
    return head->next == head;
}

void list_assert_correct(struct list_head *head);

static inline struct list_head *list_first_element(struct list_head *head)
{
    if (unlikely(list_is_empty(head)))
        return NULL;
    return head->next;
}

static inline struct list_head *list_last_element(struct list_head *head)
{
    if (unlikely(list_is_empty(head)))
        return NULL;
    return head->prev;
}

static inline void list_reset(struct list_head *head)
{
    INIT_LIST_HEAD(head);
}

#define list_for_every(lh) for (struct list_head *l = (lh)->next; l != (lh); l = l->next)

/* Again, this one is also very clearly inspired by linux */
#define list_for_every_safe(lh)                                           \
    for (struct list_head *l = (lh)->next, *____tmp = l->next; l != (lh); \
         l = ____tmp, ____tmp = l->next)

static inline void list_copy(struct list_head *dest, const list_head *src)
{
    dest->prev = src->prev;
    dest->next = src->next;

    // Fixup the pointers that should point to the head of the list (next->prev and prev->next,
    // since those are the edges).

    dest->next->prev = dest;
    dest->prev->next = dest;
}

static inline void list_move(struct list_head *dest, struct list_head *src)
{
    list_copy(dest, src);
    list_reset(src);
}

/*
 * TODO: This code is weird, inconsistent, and needs to be rewritten
 * and re-thought.
 */
struct extrusive_list_head
{
    void *ptr;
    struct extrusive_list_head *next;
};

static inline int extrusive_list_add(struct extrusive_list_head *list, void *ptr)
{
    struct extrusive_list_head *new_item =
        (struct extrusive_list_head *) malloc(sizeof(struct extrusive_list_head));
    if (!new_item)
        return -1;
    new_item->ptr = ptr;
    new_item->next = NULL;

    while (list->next)
        list = list->next;

    list->next = new_item;
    return 0;
}

static inline void *extrusive_list_get_element(struct extrusive_list_head *list, void **saveptr)
{
    if (!*saveptr)
    {
        *saveptr = list;
        return list->ptr;
    }
    else
    {
        struct extrusive_list_head *current = (struct extrusive_list_head *) *saveptr;
        struct extrusive_list_head *next = current->next;
        *saveptr = next;
        if (!next)
            return NULL;
        return next->ptr;
    }
}

static inline void extrusive_list_remove(struct extrusive_list_head *list, void *ptr)
{
    if (list->ptr == ptr)
    {
        list->ptr = NULL;
        return;
    }

    for (struct extrusive_list_head *l = list; l->next; l = l->next)
    {
        if (l->next->ptr == ptr)
        {
            struct extrusive_list_head *a = l->next;
            l->next = a->next;
            free(a);
            return;
        }
    }
}

struct list_node
{
    void *ptr;
    struct list_node *prev, *next;
};

struct list
{
    struct list_node *head, *tail;
};

static inline int list_add_node(struct list *l, void *ptr)
{
    struct list_node *node = (struct list_node *) malloc(sizeof(struct list_node));
    if (!node)
        return -1;

    node->ptr = ptr;
    node->prev = NULL;
    node->next = NULL;

    if (l->head)
    {
        l->tail->next = node;
        node->prev = l->tail;
        l->tail = node;
    }
    else
    {
        l->head = l->tail = node;
    }

    return 0;
}

static inline int __list_remove_node(struct list *l, struct list_node *n, void *ptr)
{
    while (n != NULL)
    {
        if (n->ptr == ptr)
        {
            if (n->prev)
                n->prev->next = n->next;
            else
                l->head = n->next;

            if (n->next)
                n->next->prev = n->prev;
            else
                l->tail = n->prev;

            free(n);

            return 0;
        }

        n = n->next;
    }

    return -1;
}

static inline int list_remove_node(struct list *l, void *ptr)
{
    return __list_remove_node(l, l->head, ptr);
}

static inline void list_destroy(struct list *l)
{
    struct list_node *n = l->head;

    while (n != NULL)
    {
        struct list_node *old_n = n;
        n = n->next;
        free(old_n);
    }

    l->head = l->tail = NULL;
}
#endif
