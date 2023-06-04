/*
 * Copyright (c) 2022 - 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#include <onyx/kunit.h>
#include <onyx/radix.h>
#include <onyx/types.h>
#include <onyx/vm.h>

#include <onyx/expected.hpp>

using namespace radix;

// #define RADIX_TREE_DEBUG
//
// #define RADIX_TREE_DYNAMIC_DEBUG
#ifdef RADIX_TREE_DEBUG

#ifdef RADIX_TREE_DYNAMIC_DEBUG
static bool should_print_debug = false;
#define should_print() (should_print_debug)
#define sdbg()         (should_print_debug = true)
#define edbg()         (should_print_debug = false)
#else
#define should_print() true
#define sdbg()
#define edbg()
#endif

#define DPRINTF(fmt, ...)                           \
    do                                              \
    {                                               \
        if (should_print())                         \
            printk(fmt __VA_OPT__(, ) __VA_ARGS__); \
    } while (0);
#else
#define DPRINTF(...)
#endif

radix_tree_node *radix_tree::allocate_table()
{
    return (radix_tree_node *) zalloc(sizeof(radix_tree_node));
}

int radix_tree::grow_radix_tree(int to_order)
{
    int order_diff = to_order - order;

    for (int i = 0; i < order_diff; i++)
    {
        auto table = allocate_table();
        if (!table)
            return -ENOMEM;
        table->entries[0] = (rt_entry_t) tree;
        if (tree)
            tree->parent = table;
        tree = table;
        order++;
    }

    return 0;
}

/**
 * @brief Store a value to an index
 *
 * @param index Index to store to
 * @param value Value to store
 * @return 0 on success, negative error codes
 */
int radix_tree::store(unsigned long index, rt_entry_t value)
{
    unsigned int indices[rt_max_order];

    for (unsigned int i = 0; i < rt_max_order; i++)
    {
        indices[i] = (index >> (i * rt_entry_shift)) & rt_entry_mask;
    }

    DPRINTF("indices: ");

    int max_order_set = 0;

    for (unsigned int i = 0; i < rt_max_order; i++)
    {
        DPRINTF("%u ", indices[i]);

        if (indices[i])
            max_order_set = i + 1;
    }

    if (index == 0)
    {
        // Nothing is set, but we still need the next order
        max_order_set++;
    }

    DPRINTF("\n");

    DPRINTF("This requires an order %u\n", max_order_set);

    if (order < max_order_set)
    {
        if (grow_radix_tree(max_order_set) < 0)
            return -ENOMEM;
    }

    auto tab = tree;

    DCHECK(order != 0);

    for (unsigned int i = order - 1; i != 0; i--)
    {
        DPRINTF("Going to index %u\n", indices[i]);
        auto index = indices[i];
        rt_entry_t entry = tab->entries[index];
        if (!entry)
        {
            auto new_table = allocate_table();
            if (!new_table)
                return -ENOMEM;
            new_table->parent = tab;
            new_table->offset = index;
            tab->entries[index] = (rt_entry_t) new_table;
            entry = tab->entries[index];
        }
        tab = (radix_tree_node *) entry;
    }

    tab->entries[indices[0]] = value;

    return 0;
}

/**
 * @brief Fetch a value
 *
 * @param index  Index to fetch from
 * @return Expected with the value, or negative error codes
 */
expected<rt_entry_t, int> radix_tree::get(unsigned long index)
{
    unsigned int indices[rt_max_order];

    for (unsigned int i = 0; i < rt_max_order; i++)
    {
        indices[i] = (index >> (i * rt_entry_shift)) & rt_entry_mask;
    }

    int max_order_set = 0;

    for (unsigned int i = 0; i < rt_max_order; i++)
    {
        DPRINTF("%u ", indices[i]);

        if (indices[i])
            max_order_set = i + 1;
    }

    if (index == 0)
    {
        // Nothing is set, but we still need the next order
        max_order_set++;
    }

    if (max_order_set > order)
        return unexpected{-ENOENT};

    auto tab = tree;

    for (unsigned int i = order - 1; i != 0; i--)
    {
        auto index = indices[i];
        rt_entry_t entry = tab->entries[index];
        DPRINTF("Going to index %u\n", indices[i]);
        if (!entry)
        {
            return unexpected{-ENOENT};
        }

        tab = (radix_tree_node *) entry;
    }

    const auto val = tab->entries[indices[0]];

    if (!val)
        return unexpected{-ENOENT};
    return val;
}

/**
 * @brief Clear a level of the radix tree
 * Note: Invokes itself recursively
 *
 * @param level Level (L0 is the base, Lorder-1 is the max)
 * @param table Table to clear
 */
void radix_tree::clear_level(int level, radix_tree_node *table)
{
    for (size_t i = 0; i < rt_nr_entries; i++)
    {
        auto entry = table->entries[i];

        if (!entry)
            continue;
        if (level != order - 1)
        {
            DPRINTF("Deleting L%u table %lx\n", level + 1, entry);
            clear_level(level + 1, (radix_tree_node *) entry);
        }
        else
        {
            DPRINTF("Deleting value entry %lx (table %p index %zu)\n", entry, table, i);
        }

        table->entries[i] = 0;
    }

    free(table);
}

/**
 * @brief Clear a radix tree
 *
 */
void radix_tree::clear()
{
    if (tree)
    {
        clear_level(0, tree);
        tree = nullptr;
    }
}

radix_tree::~radix_tree()
{
    clear();
}

/**
 * @brief Copy a radix tree level
 *
 * @param level Level (L0 is the base, Lorder-1 is the max)
 * @param table Original table
 * @param cb Callback for entry copying
 * @param ctx Context for entry copying's callback
 * @return Expected containing new table, or negative error code
 */
expected<radix_tree_node *, int> radix_tree::copy_level(int level, const radix_tree_node *table,
                                                        copy_cb_t cb, void *ctx)
{
    size_t i = 0;
    radix_tree_node *t = allocate_table();
    if (!t)
        return unexpected{-ENOMEM};

    for (i = 0; i < rt_nr_entries; i++)
    {
        t->entries[i] = table->entries[i];

        const auto entry = table->entries[i];

        if (!entry)
            continue;

        if (level != order - 1)
        {
            // Copy the next level
            auto ex = copy_level(level + 1, (const radix_tree_node *) entry, cb, ctx);

            if (ex.has_error())
                goto out_err;

            t->entries[i] = (rt_entry_t) ex.value();
            ex.value()->offset = i;
        }
        else
        {
            t->entries[i] = cb(table->entries[i], ctx);
        }
    }

    return t;

out_err:
    // Clear the levels we allocated

    assert(level != order - 1);
    for (; i-- > 0;)
    {
        radix_tree_node *entry = (radix_tree_node *) t->entries[i];

        clear_level(level + 1, entry);
    }

    free(t);

    return unexpected{-ENOMEM};
}

/**
 * @brief Create a copy of a radix tree
 *
 * @param cb Callback called for entry copying
 * @param ctx Context for the copy callback
 * @return Expected containing the radix_tree, or error code.
 */
expected<radix_tree, int> radix_tree::copy(copy_cb_t cb, void *ctx)
{
    radix_tree t;

    if (!tree) [[unlikely]]
        return cul::move(t);

    t.tree = tree;
    t.order = order;

    auto ex = copy_level(0, tree, cb, ctx);

    if (ex.has_error())
        return unexpected<int>{ex.error()};

    t.tree = ex.value();

    return cul::move(t);
}

radix_tree::cursor radix_tree::cursor::from_range(radix_tree *tree, unsigned long start,
                                                  unsigned long end)
{
    radix_tree::cursor c{tree, end};
    c.current_location = start;

    unsigned int indices[rt_max_order];

    for (unsigned int i = 0; i < rt_max_order; i++)
    {
        indices[i] = (start >> (i * rt_entry_shift)) & rt_entry_mask;
    }

    int max_order_set = 0;

    for (unsigned int i = 0; i < rt_max_order; i++)
    {
        if (indices[i])
            max_order_set = i + 1;
    }

    if (start == 0)
    {
        // Nothing is set, but we still need the next order
        max_order_set++;
    }

    // If max_order_set > order, there's certainly no entry for us. So just return an empty iterator
    if (max_order_set > tree->order)
        return c;

    auto tab = tree->tree;
    int depth = 0;

    for (unsigned int i = tree->order - 1; i != 0; i--, depth++)
    {
        auto index = indices[i];
        rt_entry_t entry = tab->entries[index];
        DPRINTF("Going to index %u\n", indices[i]);
        if (!entry)
            break;

        tab = (radix_tree_node *) entry;
    }

    c.current = tab;
    c.current_index = indices[tree->order - depth - 1];
    c.depth = depth;

    if (depth != tree->order - 1 || !tab->entries[c.current_index])
    {
        // Attempt to advance the iterator to the next one
        c.advance();
        DCHECK(c.is_end() || c.depth == tree->order - 1);
    }

    return c;
}

#define GET_RA_ENTRY_INDEX(index, level) (((index) >> ((level) *rt_entry_shift)) & rt_entry_mask)

void radix_tree::cursor::advance()
{
    DCHECK(!is_end());

    if (current_location == -1ul)
    {
        current = nullptr;
        return;
    }

    // We can be entering this function when not-in-the-bottom, so calculate the starting increment
    // for current_location.
    const auto curr_level_inc = 1UL << (rt_entry_shift * (tree_->order - depth - 1));
    current_index++;
    current_location = (current_location + curr_level_inc) & -curr_level_inc;

    while (current && current_location <= end)
    {
        DPRINTF("current %p, curidx %lx, tabidx %x, end %lx, depth %d\n", current, current_location,
                current_index, end, depth);
        DPRINTF("tree order %d\n", tree_->order);
        const unsigned long level_increment = 1UL << (rt_entry_shift * (tree_->order - depth - 1));

        if (current_index == rt_nr_entries)
        {
            DPRINTF("going up to depth %d\n", depth);
            // Ok, we've ran out of entries in this node, lets go up. Let's calculate current_index
            // out of the current location.
            current_index = current->offset + 1;
            depth--;
            // ... and go up
            current = current->parent;
            DPRINTF("Current: %p\n", current);
            continue;
        }

        auto entry = current->entries[current_index];

        if (entry)
        {
            DPRINTF("Entry found\n");
            // Great, we found an entry.
            if (depth == tree_->order - 1)
                return;
            DPRINTF("...node table\n");
            // Ok, this is a table, let's go down
            current = (radix_tree_node *) entry;
            depth++;
            // Check if current_location has an aligned index
            DCHECK(GET_RA_ENTRY_INDEX(current_location, tree_->order - depth - 1) == 0);
            current_index = 0;
            continue;
        }

        // Advance a single position in the current table
        current_index++;
        // The new location will be a level_increment aligned index. Note that we always align
        // up, hence + level_increment (instead of level_increment - 1 as in a normal ALIGN_TO).
        DPRINTF("level inc for depth %d: %lx\n", depth, level_increment);
        const auto next = (current_location + level_increment) & -level_increment;

        if (next < current_location)
        {
            // Ooops, we have overflowed when calculating this index. This means we've ran out
            // of table.
            current = nullptr;
            return;
        }

        current_location = next;
    }
}

void radix_tree::cursor::store(rt_entry_t new_val)
{
    DCHECK(!is_end());
    current->entries[current_index] = new_val;
    // TODO: If 0, free? We need to keep a counter of filled entries instead of scanning the whole
    // table. We have a bunch of space we should use for XA marks, etc due to the slab allocator's
    // allocation properties.
}

#ifdef CONFIG_KUNIT

TEST(radix, basic_store_test)
{
    radix_tree tree;
    tree.store(10, 0x100100);
    tree.store(0x401, 0x10000);
    tree.store(0xffffffffffffffff, 0x10000);

    auto out0 = tree.get(10);
    auto out1 = tree.get(0x401);
    auto out2 = tree.get(0xffffffffffffffff);
    ASSERT_TRUE(out0.has_value());
    ASSERT_TRUE(out1.has_value());
    ASSERT_TRUE(out2.has_value());

    EXPECT_EQ(out0.value(), 0x100100ul);
    EXPECT_EQ(out1.value(), 0x10000ul);
    EXPECT_EQ(out2.value(), 0x10000ul);
}

TEST(radix, iterator_test)
{
    radix_tree tree;
    tree.store(10, 0x100100);
    tree.store(0x401, 0x10000);
    tree.store(0xffffffffffffffff, 0x10000);

    auto out0 = tree.get(10);
    auto out1 = tree.get(0x401);
    auto out2 = tree.get(0xffffffffffffffff);
    ASSERT_TRUE(out0.has_value());
    ASSERT_TRUE(out1.has_value());
    ASSERT_TRUE(out2.has_value());

    auto cursor = radix_tree::cursor::from_range(&tree, 10);

    ASSERT_FALSE(cursor.is_end());
    ASSERT_EQ(10ul, cursor.current_idx());
    ASSERT_EQ(0x100100ul, cursor.get());
    cursor.advance();
    ASSERT_FALSE(cursor.is_end());
    ASSERT_EQ(0x401ul, cursor.current_idx());
    ASSERT_EQ(0x10000ul, cursor.get());
    cursor.advance();
    ASSERT_FALSE(cursor.is_end());
    ASSERT_EQ(0xfffffffffffffffful, cursor.current_idx());
    ASSERT_EQ(0x10000ul, cursor.get());
    cursor.advance();
    ASSERT_TRUE(cursor.is_end());
}

TEST(radix, iterator_fast_forwards)
{
    // Test if from_range(&tree, 0) can get past the absence of index 0 and find 10
    radix_tree tree;
    tree.store(10, 0x100100);
    tree.store(0x401, 0x10000);
    tree.store(0xffffffffffffffff, 0x10000);

    auto out0 = tree.get(10);
    auto out1 = tree.get(0x401);
    auto out2 = tree.get(0xffffffffffffffff);
    ASSERT_TRUE(out0.has_value());
    ASSERT_TRUE(out1.has_value());
    ASSERT_TRUE(out2.has_value());

    auto cursor = radix_tree::cursor::from_range(&tree, 0);

    ASSERT_FALSE(cursor.is_end());
    ASSERT_EQ(10ul, cursor.current_idx());
    ASSERT_EQ(0x100100ul, cursor.get());
    cursor.advance();
    ASSERT_FALSE(cursor.is_end());
    ASSERT_EQ(0x401ul, cursor.current_idx());
    ASSERT_EQ(0x10000ul, cursor.get());
    cursor.advance();
    ASSERT_FALSE(cursor.is_end());
    ASSERT_EQ(0xfffffffffffffffful, cursor.current_idx());
    ASSERT_EQ(0x10000ul, cursor.get());
    cursor.advance();
    ASSERT_TRUE(cursor.is_end());

    // Now test this functionality for depth != 0 here (where we need to traverse the tree up and
    // down.)
    cursor = radix_tree::cursor::from_range(&tree, 0x100);
    ASSERT_FALSE(cursor.is_end());
    ASSERT_EQ(0x401ul, cursor.current_idx());
    ASSERT_EQ(0x10000ul, cursor.get());
    cursor.advance();
    ASSERT_FALSE(cursor.is_end());
    ASSERT_EQ(0xfffffffffffffffful, cursor.current_idx());
    ASSERT_EQ(0x10000ul, cursor.get());
    cursor.advance();
    ASSERT_TRUE(cursor.is_end());
}

TEST(radix, sixteen_mb)
{
    // Regression test for iteration: we were wrongly calculating the upper level's index when going
    // upwards, which made for infinite loops when iterating.
    radix_tree tree;
    for (int i = 0; i < 4096; i++)
        tree.store(i, i + 1);
    int last = -1;
    tree.for_every_entry([&last](rt_entry_t val, unsigned long off) -> bool {
        DCHECK(last == (int) off - 1);
        last = off;
        DCHECK(val == off + 1);
        DCHECK(off < 4096);
        return true;
    });
}

#endif
