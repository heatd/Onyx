/*
 * Copyright (c) 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include <stdio.h>

#include <lib/binary_search_tree.h>
#include <onyx/kunit.h>

// Test augmented binary search trees using structures similar to vm_area_structs

struct vma
{
    unsigned long vma_start;
    unsigned long vma_size;
    unsigned long vma_gap;
    struct bst_node vma_node;
};

unsigned long vma_compute_gap(struct vma *vma)
{
    /* Bastardized version of a real vm allocation algorithm but flawed as we
     * only take into account the gap of our children. Nevertheless, should work as an example.
     */
    unsigned long largest_gap = 0;

    if (vma->vma_node.child[0] && vma->vma_node.child[1])
    {
        struct vma *vma0 = container_of(vma->vma_node.child[0], struct vma, vma_node);
        struct vma *vma1 = container_of(vma->vma_node.child[1], struct vma, vma_node);
        largest_gap = vma1->vma_start - (vma0->vma_start + vma0->vma_size);
    }

    return largest_gap;
}

BST_AUGMENTED(vma_aug, struct vma, vma_node, unsigned long, vma_gap, vma_compute_gap);

template <int N>
class vma_depot
{
    struct vma vmas_[N];
    int used = 0;
public:
    struct vma *get()
    {
        assert(used < N);
        struct vma *v = &vmas_[used++];
        v->vma_start = 0;
        v->vma_size = 0;
        v->vma_gap = 0;
        bst_node_initialize(&v->vma_node);
        return v;
    }
};

class vma_tree
{
public:
    struct bst_root vma_root = BST_ROOT_INITIAL_VALUE;
    bool insert(struct vma *vma, unsigned long start, unsigned long len)
    {
        struct bst_node **nodep, *parent, *cur;
        auto compare = [](struct bst_node *lhs_, struct bst_node *rhs_) -> int {
            auto lhs = container_of(lhs_, struct vma, vma_node);
            auto rhs = container_of(rhs_, struct vma, vma_node);

            if (check_for_overlap(lhs->vma_start, lhs->vma_start + lhs->vma_size - 1, rhs->vma_start,
                                  rhs->vma_start + rhs->vma_size - 1))
            {
                return 0;
            }
            else if (rhs->vma_start > lhs->vma_start)
                return 1;
            else
                return -1;
        };

        vma->vma_start = start;
        vma->vma_size = len;
        vma->vma_gap = 1; // force propagate to really propagate, in this case

        cur = vma_root.root;
        nodep = &vma_root.root;
        parent = nullptr;

        while (cur)
        {
            int res = compare(cur, &vma->vma_node);

            if (res == 0)
                return false;
            parent = cur;
            nodep = &cur->child[res > 0];
            cur = *nodep;
        }

        bst_link(nodep, parent, &vma->vma_node);
        vma_aug_propagate(&vma->vma_node, nullptr);
        bst_update_rank_insert(&vma_root, &vma->vma_node, &vma_aug);
        return true;
    }

    void del(struct vma *vma)
    {
        bst_delete_augmented(&vma_root, &vma->vma_node, &vma_aug);
    }
};

TEST(augmented_bst, test_insert)
{
    // Test augmented propagation on inserts, without rotations!
    vma_depot<3> depot;
    vma_tree tree;
    struct vma *vma = depot.get(), *vma2 = depot.get(), *vma3 = depot.get();

    ASSERT_TRUE(tree.insert(vma, 0x2000, 0x1000));
    ASSERT_TRUE(tree.insert(vma2, 0x1000, 0x1000));
    ASSERT_TRUE(tree.insert(vma3, 0x3000, 0x1000));

    // Tree looks like:
    //             [0x2000, 0x3000]
    //            /                \.
    // [0x1000, 0x2000]        [0x3000, 0x4000]
    //                    |
    //           We should have a gap of 0x1000
    EXPECT_EQ(0x1000UL, vma->vma_gap);
    EXPECT_EQ(0UL, vma2->vma_gap);
    EXPECT_EQ(0UL, vma3->vma_gap);
}

TEST(augmented_bst, test_propagate)
{
    // Test that the default generated augmented propagation works
    vma_depot<3> depot;
    vma_tree tree;
    struct vma *vma = depot.get(), *vma2 = depot.get(), *vma3 = depot.get();

    ASSERT_TRUE(tree.insert(vma, 0x2000, 0x1000));
    ASSERT_TRUE(tree.insert(vma2, 0x1000, 0x1000));
    ASSERT_TRUE(tree.insert(vma3, 0x3000, 0x1000));

    // Tree looks like:
    //             [0x2000, 0x3000]
    //            /                \.
    // [0x1000, 0x2000]        [0x3000, 0x4000]
    //                    |
    //           We should have a gap of 0x1000
    EXPECT_EQ(0x1000UL, vma->vma_gap);
    EXPECT_EQ(0UL, vma2->vma_gap);
    EXPECT_EQ(0UL, vma3->vma_gap);

    // Change vma3's start and propagate
    vma3->vma_start += 0x1000;
    vma3->vma_gap = 1; // force it to propagate
    vma_aug_propagate(&vma3->vma_node, nullptr);

    EXPECT_EQ(0x2000UL, vma->vma_gap);
    EXPECT_EQ(0UL, vma3->vma_gap);
}

TEST(augmented_bst, test_insert_rotations)
{
    vma_depot<5> depot;
    vma_tree tree;
    struct vma *vma = depot.get(), *vma2, *vma3, *vma4;
    (void) vma3;
    (void) vma4;
    struct vma *rootvma = vma;
    ASSERT_EQ(true, tree.insert(vma, 0x10000, 0x1000));

    // Tree looks like:
    //      [0x10000, 0x11000] - no gap
    //
    ASSERT_EQ(0UL, vma->vma_gap);

    vma = depot.get();
    ASSERT_EQ(true, tree.insert(vma, 0x13000, 0x1000));

    // Tree looks like:
    //      [0x10000, 0x11000]
    //                   \.
    //                 [0x13000, 0x14000] - no gap
    ASSERT_EQ(0UL, vma->vma_gap);
    ASSERT_EQ(0UL, rootvma->vma_gap);
    
    vma2 = depot.get();
    ASSERT_EQ(true, tree.insert(vma2, 0x120000, 0x1000));

    // Tree looks like:
    //             [0x13000, 0x14000]
    //            /                \.
    // [0x10000, 0x11000]        [0x120000, 0x121000]
    //                    |
    //           We should have a gap!
    ASSERT_EQ(0x120000 - 0x11000UL, vma->vma_gap);
    ASSERT_EQ(0UL, rootvma->vma_gap);
    ASSERT_EQ(0UL, vma2->vma_gap);
}

TEST(augmented_bst, test_delete0)
{
    // Test augmented propagation on deletes, without rotations!
    vma_depot<3> depot;
    vma_tree tree;
    struct vma *vma = depot.get(), *vma2 = depot.get(), *vma3 = depot.get();

    ASSERT_TRUE(tree.insert(vma, 0x2000, 0x1000));
    ASSERT_TRUE(tree.insert(vma2, 0x1000, 0x1000));
    ASSERT_TRUE(tree.insert(vma3, 0x3000, 0x1000));

    // Tree looks like:
    //             [0x2000, 0x3000]
    //            /                \.
    // [0x1000, 0x2000]        [0x3000, 0x4000]
    //                    |
    //           We should have a gap of 0x1000
    EXPECT_EQ(0x1000UL, vma->vma_gap);
    EXPECT_EQ(0UL, vma2->vma_gap);
    EXPECT_EQ(0UL, vma3->vma_gap);

    tree.del(vma);

    EXPECT_EQ(0UL, vma2->vma_gap);
    EXPECT_EQ(0UL, vma3->vma_gap);
}

TEST(augmented_bst, test_delete1)
{
    // Test augmented propagation on deletes, without rotations!
    vma_depot<3> depot;
    vma_tree tree;
    struct vma *vma = depot.get(), *vma2 = depot.get(), *vma3 = depot.get();

    ASSERT_TRUE(tree.insert(vma, 0x2000, 0x1000));
    ASSERT_TRUE(tree.insert(vma2, 0x1000, 0x1000));
    ASSERT_TRUE(tree.insert(vma3, 0x3000, 0x1000));

    // Tree looks like:
    //             [0x2000, 0x3000]
    //            /                \.
    // [0x1000, 0x2000]        [0x3000, 0x4000]
    //                    |
    //           We should have a gap of 0x1000
    EXPECT_EQ(0x1000UL, vma->vma_gap);
    EXPECT_EQ(0UL, vma2->vma_gap);
    EXPECT_EQ(0UL, vma3->vma_gap);

    tree.del(vma2);

    EXPECT_EQ(0UL, vma->vma_gap);
    EXPECT_EQ(0UL, vma3->vma_gap);
}
