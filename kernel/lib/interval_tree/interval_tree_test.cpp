/*
 * Copyright (c) 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <stdio.h>

#include <onyx/interval_tree.h>
#include <onyx/kunit.h>

static void add_range(struct interval_tree_root *root, struct interval_tree_node *node,
                      unsigned long start, unsigned long end)
{
    interval_tree_node_init(node, start, end);
    interval_tree_insert(root, node);
}

TEST(interval_tree, insert)
{
#define IT_SEEN 0xDEADUL
    struct interval_tree_node nodes[4];
    interval_tree_root tree;
    interval_tree_root_init(&tree);
    add_range(&tree, &nodes[0], 0, 10);
    add_range(&tree, &nodes[1], 1, 3);
    add_range(&tree, &nodes[2], 32, 1000);
    add_range(&tree, &nodes[3], 8, 15);

    struct interval_tree_node *entry;
    int i = 0;
    __for_intervals_in_range(&tree, entry, 1, 8)
    {
        entry->start = IT_SEEN + i++;
    }

    EXPECT_EQ(nodes[0].start, IT_SEEN);
    EXPECT_EQ(nodes[1].start, IT_SEEN + 1);
    EXPECT_NE(nodes[2].start, IT_SEEN + 2);
    EXPECT_EQ(nodes[3].start, IT_SEEN + 2);
#undef IT_SEEN
}

TEST(interval_tree, insert2)
{
#define IT_SEEN 0xDEADUL
    struct interval_tree_node nodes[4];
    interval_tree_root tree;
    interval_tree_root_init(&tree);
    add_range(&tree, &nodes[0], 4, 10);
    add_range(&tree, &nodes[1], 1, 3);
    add_range(&tree, &nodes[2], 1, 4);
    add_range(&tree, &nodes[3], 8, 15);

    struct interval_tree_node *entry;
    int i = 0;
    __for_intervals_in_range(&tree, entry, 0, 8)
    {
        entry->start = IT_SEEN + i++;
    }

    EXPECT_GE(nodes[0].start, IT_SEEN);
    EXPECT_GE(nodes[1].start, IT_SEEN);
    EXPECT_GE(nodes[2].start, IT_SEEN);
    EXPECT_GE(nodes[3].start, IT_SEEN);
#undef IT_SEEN
}

TEST(interval_tree, iterate_empty)
{
    struct interval_tree_node nodes[4];
    interval_tree_root tree;
    interval_tree_root_init(&tree);
    add_range(&tree, &nodes[0], 4, 5);
    add_range(&tree, &nodes[1], 1, 3);
    add_range(&tree, &nodes[2], 1, 4);
    add_range(&tree, &nodes[3], 8, 15);

    int i = 0;
    struct interval_tree_node *entry;

    /* Iterate on an empty range (to the right) */
    __for_intervals_in_range(&tree, entry, 16, 20)
    {
        i++;
    }

    ASSERT_EQ(0, i);

    /* Iterate on an empty range (in the middle of the tree) */

    __for_intervals_in_range(&tree, entry, 6, 7)
    {
        i++;
    }

    ASSERT_EQ(0, i);
}

TEST(interval_tree, remove_works)
{
    struct interval_tree_node nodes[4];
    interval_tree_root tree;
    interval_tree_root_init(&tree);
    add_range(&tree, &nodes[0], 4, 10);
    add_range(&tree, &nodes[1], 1, 3);
    add_range(&tree, &nodes[2], 1, 4);
    add_range(&tree, &nodes[3], 9, 15);

    struct interval_tree_node *entry;
    int i = 0;
    __for_intervals_in_range(&tree, entry, 0, 8)
    {
        i++;
    }

    EXPECT_EQ(3, i);
    i = 0;
    interval_tree_remove(&tree, &nodes[1]);
    interval_tree_remove(&tree, &nodes[0]);
    __for_intervals_in_range(&tree, entry, 0, 8)
    {
        i++;
    }

    EXPECT_EQ(1, i);
}
