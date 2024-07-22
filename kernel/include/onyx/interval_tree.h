/*
 * Copyright (c) 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#ifndef _ONYX_INTERVAL_TREE_H
#define _ONYX_INTERVAL_TREE_H

#include <lib/binary_search_tree.h>

#include <onyx/assert.h>
#include <onyx/compiler.h>

#ifdef __cplusplus
#define CONSTEXPR constexpr
#else
#define CONSTEXPR
#endif

struct interval_tree_root
{
    struct bst_root root;
};

struct interval_tree_node
{
    struct bst_node node;
    unsigned long start;
    unsigned long end;
    unsigned long max_end;
};

CONSTEXPR
static inline void interval_tree_root_init(struct interval_tree_root *root)
{
    bst_root_initialize(&root->root);
}

CONSTEXPR
static inline void interval_tree_node_init(struct interval_tree_node *node, unsigned long start,
                                           unsigned long end)
{
    bst_node_initialize(&node->node);
    node->start = start;
    node->end = end;
}

__BEGIN_CDECLS

/**
 * @brief Insert an interval onto the interval tree
 *
 * @param root Tree to insert on
 * @param node Node to insert
 */
void interval_tree_insert(struct interval_tree_root *root, struct interval_tree_node *node);

/**
 * @brief Remove an interval from the interval tree
 *
 * @param root Interval tree root
 * @param node Interval to remove
 */
void interval_tree_remove(struct interval_tree_root *root, struct interval_tree_node *node);

static inline struct interval_tree_node *__interval_tree_search(
    const struct interval_tree_root *root, unsigned long start, unsigned long end)
{
    /* We may not use bst_search because it won't quite work with our interval tree that /may/
     * contain duplicates.
     */
    DCHECK(root);

    struct bst_node *tree_node = root->root.root;

    /* We go through the tree and find the smallest node that matches our range in a normal-ish bst
     * fashion.
     */
    while (tree_node)
    {
        struct interval_tree_node *node = container_of(tree_node, struct interval_tree_node, node);
        struct interval_tree_node *left =
            containerof_null_safe(node->node.child[0], struct interval_tree_node, node);
        int cmp = -2;

        if (left)
        {
            /* Check if left has any nodes in our range */
            if (left->max_end >= start)
                cmp = -1; /* If so, go left */
        }

        if (cmp == -2)
        {
            /* Do a standard bst cmp */
            if (node->start <= end && start <= node->end)
                cmp = 0;
            else
                cmp = start < node->start ? -1 : 1;
        }

        if (!cmp)
        {
            /* Note: smaller nodes are already covered by the if (left) up there */
            return node;
        }

        tree_node = tree_node->child[cmp > 0];
    }

    return NULL;
}

static inline struct interval_tree_node *__interval_tree_next(struct interval_tree_root *root,
                                                              struct interval_tree_node *node,
                                                              unsigned long start,
                                                              unsigned long end)
{
    DCHECK(root);
    DCHECK(node);
    struct bst_node *next = bst_next(&root->root, &node->node);
    if (!next)
        return NULL;

    struct interval_tree_node *next_node = container_of(next, struct interval_tree_node, node);
    if (next_node->start <= end && start <= next_node->end)
        return next_node;
    return NULL;
}

#define __for_intervals_in_range(root, entry, start, end)                              \
    for (struct interval_tree_node *__node = __interval_tree_search(root, start, end); \
         ((entry) = __node) != NULL; __node = __interval_tree_next(root, __node, start, end))

#define for_intervals_in_range(root, entry, type, member, start, end)                  \
    for (struct interval_tree_node *__node = __interval_tree_search(root, start, end); \
         __node && ((entry) = container_of(__node, type, member));                     \
         __node = __interval_tree_next(root, __node, start, end))

__END_CDECLS

#endif
