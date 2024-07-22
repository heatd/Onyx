/*
 * Copyright (c) 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <onyx/interval_tree.h>

#define MAX(a, b) ((a) > (b) ? (a) : (b))

static unsigned long interval_tree_max_compute(struct interval_tree_node *node)
{
    unsigned long max = node->end;
    const struct interval_tree_node *left =
        containerof_null_safe(node->node.child[0], struct interval_tree_node, node);
    const struct interval_tree_node *right =
        containerof_null_safe(node->node.child[1], struct interval_tree_node, node);

    if (left)
        max = MAX(max, left->max_end);
    if (right)
        max = MAX(max, right->max_end);
    return max;
}

BST_AUGMENTED(interval_tree, struct interval_tree_node, node, unsigned long, max_end,
              interval_tree_max_compute);

/**
 * @brief Insert an interval onto the interval tree
 *
 * @param root Tree to insert on
 * @param node Node to insert
 */
void interval_tree_insert(struct interval_tree_root *root, struct interval_tree_node *node)
{
    struct bst_node **nodep, *parent, *cur;

    cur = root->root.root;
    nodep = &root->root.root;
    parent = NULL;

    while (cur)
    {
        struct interval_tree_node *__node = container_of(cur, struct interval_tree_node, node);
        int res = node->start < __node->start ? -1 : 1;

        parent = cur;
        nodep = &cur->child[res > 0];
        cur = *nodep;
    }

    bst_link(nodep, parent, &node->node);
    interval_tree_propagate(&node->node, NULL);
    bst_update_rank_insert(&root->root, &node->node, &interval_tree);
}

/**
 * @brief Remove an interval from the interval tree
 *
 * @param root Interval tree root
 * @param node Interval to remove
 */
void interval_tree_remove(struct interval_tree_root *root, struct interval_tree_node *node)
{
    bst_delete_augmented(&root->root, &node->node, &interval_tree);
}
