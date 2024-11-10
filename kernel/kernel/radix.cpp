/*
 * Copyright (c) 2022 - 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#include <onyx/kunit.h>
#include <onyx/mm/slab.h>
#include <onyx/page.h>
#include <onyx/radix.h>
#include <onyx/types.h>

#include <onyx/expected.hpp>

using namespace radix;

// #define RADIX_TREE_DEBUG
//
// #define RADIX_TREE_DYNAMIC_DEBUG
#ifdef RADIX_TREE_DEBUG

#ifdef RADIX_TREE_DYNAMIC_DEBUG
bool should_print_debug = false;
#define should_print() (should_print_debug)
#define sdbg()         (should_print_debug = true)
#define edbg()         (should_print_debug = false)
#else
#define should_print() true
#define sdbg()
#define edbg()
#endif

#define DPRINTF(fmt, ...)                                     \
    do                                                        \
    {                                                         \
        if (should_print())                                   \
            printk(KERN_WARN fmt __VA_OPT__(, ) __VA_ARGS__); \
    } while (0);
#else
#define DPRINTF(...)
#endif

static slab_cache *node_cache;

__init static void radix_init_slab()
{
    node_cache = kmem_cache_create("radix_tree_node", sizeof(radix_tree_node), 0,
                                   KMEM_CACHE_HWALIGN | KMEM_CACHE_VMALLOC, nullptr);
    CHECK(node_cache != nullptr);
}

radix_tree_node *radix_tree::allocate_table()
{
    auto node = kmem_cache_alloc(node_cache, GFP_ATOMIC);
    if (!node) [[unlikely]]
        return nullptr;
    memset(node, 0, sizeof(radix_tree_node));
    return (radix_tree_node *) node;
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
        {
            tree->parent = table;
            // Propagate tags by setting bits if the child's marks bitmap is not empty
            for (unsigned int j = 0; j < nr_marks; j++)
            {
                if (!tree->mark_empty(j))
                    table->marks[j][0] |= (1UL << 0);
            }
        }

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

    if (!value)
        clear_all_tags(tab, indices[0]);
    else
        propagate_tag(tab, indices[0], RA_MARK_PRESENT, true);

    return 0;
}

unsigned long radix_tree::xchg(unsigned long index, rt_entry_t value)
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

    unsigned long old = tab->entries[indices[0]];
    tab->entries[indices[0]] = value;

    if (!value)
        clear_all_tags(tab, indices[0]);
    else
        propagate_tag(tab, indices[0], RA_MARK_PRESENT, true);

    return old;
}
/**
 * @brief Fetch a value
 *
 * @param index  Index to fetch from
 * @return Expected with the value, or negative error codes
 */
expected<rt_entry_t, int> radix_tree::get(unsigned long index)
{
    radix_tree_node *tab;
    unsigned int tabindex;
    if (!get_table_entry(index, &tab, &tabindex))
        return unexpected{-ENOENT};

    const auto val = tab->entries[tabindex];

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

    kmem_cache_free(node_cache, table);
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

    for (i = 0; i < nr_marks; i++)
    {
        for (size_t j = 0; j < radix_tree_node::marks_nr_entries; j++)
            t->marks[i][j] = table->marks[i][j];
    }

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

            radix_tree_node *node = ex.value();

            t->entries[i] = (rt_entry_t) node;
            node->offset = i;
            node->parent = t;
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

    kmem_cache_free(node_cache, t);

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

radix_tree::cursor radix_tree::cursor::from_range_on_marks(radix_tree *tree, unsigned int mark,
                                                           unsigned long start, unsigned long end)
{
    radix_tree::cursor c{tree, end};
    c.current_location = start;
    c.mark = mark;

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

    if (depth != tree->order - 1 || !tab->check_mark(mark, c.current_index))
    {
        // Attempt to advance the iterator to the next one
        c.advance();
        DCHECK(c.is_end() || c.depth == tree->order - 1);
    }

    return c;
}

#define GET_RA_ENTRY_INDEX(index, level) (((index) >> ((level) *rt_entry_shift)) & rt_entry_mask)

/**
 * @brief Find the next index to the given mark
 *
 * @return Next index. If not found, returns radix::nr_entries.
 */
unsigned int radix_tree::cursor::find_next_index()
{
    static constexpr int bits_per_long = sizeof(unsigned long) * 8;
    unsigned int bitmap_index = (current_index + 1) / bits_per_long;
    unsigned int wordshift = (current_index + 1) % bits_per_long;
    for (unsigned int i = bitmap_index; i < radix_tree_node::marks_nr_entries; i++, wordshift = 0)
    {
        unsigned long word = current->marks[mark][i] >> wordshift;

        if (!word)
            continue;
        unsigned int first_set = __builtin_ffsl(word) - 1;
        return first_set + wordshift + (i * bits_per_long);
    }

    return radix::rt_nr_entries;
}

/**
 * @brief Move the index to the next valid one
 *
 */
void radix_tree::cursor::move_index()
{
    const auto curr_level_inc = 1UL << (rt_entry_shift * (tree_->order - depth - 1));
    const auto old_index = current_index;
    current_index = find_next_index();
    // The new location will be a level_increment aligned index. Note that we always align
    // up, hence + level_increment (instead of level_increment - 1 as in a normal ALIGN_TO).
    // Let's move up current_location by curr_level_inc * (curr_index - old_index) to properly take
    // into account the entries we may have skipped.
    auto next =
        (current_location + (curr_level_inc * (current_index - old_index))) & -curr_level_inc;

    if (next < current_location || next > end)
    {
        // Oops, overflow! We ran out of table
        current = nullptr;
        return;
    }

    current_location = next;
}

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
    move_index();
    DPRINTF("start current %p, location %lx\n", current, current_location);

    while (current && current_location <= end)
    {
        DPRINTF("current %p, curidx %lx, tabidx %x, end %lx, depth %d\n", current, current_location,
                current_index, end, depth);
        DPRINTF("tree order %d\n", tree_->order);

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

        if (current->check_mark(mark, current_index))
        {
            auto entry = current->entries[current_index];
            DCHECK(entry != 0);
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

        // Advance positions in the current table
        move_index();
    }

    if (current_index == rt_nr_entries)
        DCHECK(current == nullptr);
}

void radix_tree::cursor::store(rt_entry_t new_val)
{
    DCHECK(!is_end());
    current->entries[current_index] = new_val;
    // TODO: If 0, free? We need to keep a counter of filled entries instead of scanning the whole
    // table. We have a bunch of space we should use for XA marks, etc due to the slab allocator's
    // allocation properties.

    // Note: we do not need to set here, because if the cursor is pointing at an entry, it must mean
    // it exists.
    if (!new_val)
        clear_all_tags(current, current_index);
}

bool radix_tree_node::mark_empty(unsigned int mark)
{
    for (unsigned int i = 0; i < radix_tree_node::marks_nr_entries; i++)
    {
        if (marks[mark][i])
            return false;
    }

    return true;
}

/**
 * @brief Given a table and the index in that table, propagate a tag up the tree
 *
 * @param table Tree node
 * @param tabindex Index in the table
 * @param mark Mark to propagate
 * @param set True if we should set, else unset
 */
void radix_tree::propagate_tag(radix_tree_node *table, unsigned int tabindex, unsigned int mark,
                               bool set)
{
    // We can't set a tag on an empty entry
    if (set && !table->entries[tabindex])
        return;
    static constexpr int bits_per_long = sizeof(unsigned long) * 8;

    unsigned long index = tabindex;

    while (table)
    {
        const unsigned int marks_index = index / bits_per_long;
        const unsigned int marks_bit = index % bits_per_long;

        if (set)
        {
            const unsigned long mask = 1UL << marks_bit;
            // If already set, break here
            if (table->marks[mark][marks_index] & mask)
                break;
            table->marks[mark][marks_index] |= mask;
        }
        else
        {
            table->marks[mark][marks_index] &= ~(1UL << marks_bit);

            // If the marks for this node aren't empty, don't go up the tree
            if (!table->mark_empty(mark))
                break;
        }

        index = table->offset;
        table = table->parent;
    }
}

/**
 * @brief Given a table and the index in that table, clear the tags and propagate them up the
 * tree.
 * Supposed to be used when clearing entries.
 *
 * @param table Tree node
 * @param tabindex Index in the table
 */
void radix_tree::clear_all_tags(radix_tree_node *table, unsigned int tabindex)
{
    static constexpr int bits_per_long = sizeof(unsigned long) * 8;

    unsigned long index = tabindex;
    /* Algorithm: we keep a bitmap of bits that are supposed to get cleared. At the beginning, it's
     * all-1s. As we go up the tree, we may find that some marks get completely emptied, others do
     * not. If a mark is not empty, we clear it from the bitmask so we don't try to erroneously
     * clear that up the tree.
     */
    u8 cleared_bits = (1U << radix::nr_marks) - 1;

    while (table)
    {
        const unsigned int marks_index = index / bits_per_long;
        const unsigned int marks_bit = index % bits_per_long;

        for (unsigned int i = 0, j = cleared_bits; i < radix::nr_marks && j != 0; i++, j >>= 1)
        {
            // If the bit is unset, skip clearing this.
            if (!(j & 1))
                continue;
            table->marks[i][marks_index] &= ~(1UL << marks_bit);
            if (!table->mark_empty(i))
            {
                cleared_bits &= ~(1U << i);
            }
        }

        if (cleared_bits == 0)
        {
            // No more bits to clear up the tree, break
            break;
        }

        index = table->offset;
        table = table->parent;
    }
}
/**
 * @brief Get the table entry for a given index
 *
 * @param index Radix tree index
 * @param table Pointer to a pointer to a table. Gets filled on success.
 * @param tabindex Pointer to a table index. Gets filled on success
 * @return True if we got the entry, else false.
 */
bool radix_tree::get_table_entry(unsigned long index, radix_tree_node **table,
                                 unsigned int *tabindex)
{
    unsigned int indices[rt_max_order];

    for (unsigned int i = 0; i < rt_max_order; i++)
    {
        indices[i] = (index >> (i * rt_entry_shift)) & rt_entry_mask;
    }

    int max_order_set = 0;

    for (unsigned int i = 0; i < rt_max_order; i++)
    {
        if (indices[i])
            max_order_set = i + 1;
    }

    if (index == 0)
    {
        // Nothing is set, but we still need the next order
        max_order_set++;
    }

    // If max_order_set > order, there's certainly no entry for us.
    if (max_order_set > order)
        return false;

    radix_tree_node *tab = tree;

    for (unsigned int i = order - 1; i != 0; i--)
    {
        auto index = indices[i];
        rt_entry_t entry = tab->entries[index];
        DPRINTF("Going to index %u\n", indices[i]);
        if (!entry)
            return false;

        tab = (radix_tree_node *) entry;
    }

    *table = tab;
    *tabindex = indices[0];

    return true;
}

/**
 * @brief Set a mark on an index
 *
 * @param index Index to mark
 * @param mark The mark to set
 */
void radix_tree::set_mark(unsigned long index, unsigned int mark)
{
    radix_tree_node *table;
    unsigned int tabindex;

    // Note: If the table entry does not exist, or the entry is NULL, just return.
    if (!get_table_entry(index, &table, &tabindex))
        return;
    if (!table->entries[tabindex])
        return;

    propagate_tag(table, tabindex, mark, true);
}

/**
 * @brief Clear a mark on an index
 *
 * @param index Index to mark
 * @param mark The mark to clear
 */
void radix_tree::clear_mark(unsigned long index, unsigned int mark)
{
    radix_tree_node *table;
    unsigned int tabindex;

    // Note: If the table entry does not exist, or the entry is NULL, just return.
    if (!get_table_entry(index, &table, &tabindex))
        return;
    if (!table->entries[tabindex])
        return;

    propagate_tag(table, tabindex, mark, false);
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

TEST(radix, check_present_tag_works)
{
    // Let's test if the present tagging works and is getting propagated up the tree
    // To test these properties, we snoop the marks array in each node
    // Note: We take advantage of certain current properties to make this test work atm.
    // The main one relies on store(0) not freeing tables.
    // We also more or less assume how the radix tree will look like and expand, but
    // this is not so serious as it relies on main concepts of a radix tree.

    radix_tree tree;

    // Test 1: Entry at the first level
    ASSERT_EQ(0, tree.store(1, 0x100));

    radix_tree_node *tab;
    unsigned int index;
    ASSERT_TRUE(tree.get_table_entry(1, &tab, &index));
    ASSERT_TRUE(tab->check_mark(RA_MARK_PRESENT, index));

    // Now let's force a second level to appear. Note that the top level should have the mark set as
    // well now, even after expanding the tree.
    ASSERT_EQ(0, tree.store(radix::rt_nr_entries, 0x100));
    ASSERT_NONNULL(tab->parent);
    EXPECT_TRUE(tab->parent->check_mark(RA_MARK_PRESENT, tab->offset));

    // Now check the radix::rt_nr_entries's present, plus the upper level too
    ASSERT_TRUE(tree.get_table_entry(radix::rt_nr_entries, &tab, &index));
    EXPECT_TRUE(tab->check_mark(RA_MARK_PRESENT, index));
    EXPECT_TRUE(tab->parent->check_mark(RA_MARK_PRESENT, tab->offset));

    // Now let's clear the entry and verify that the mark will be unset and properly propagated up
    // the tree.
    const auto upper_level = tab->parent;
    const auto table_index = tab->offset;
    ASSERT_EQ(0, tree.store(radix::rt_nr_entries, 0));
    EXPECT_FALSE(upper_level->check_mark(RA_MARK_PRESENT, table_index));

    // Now let's test that the tag does not get deleted accidentally if we clear an entry on a table
    // that still has marks.
    ASSERT_EQ(0, tree.store(0, 0x100));
    ASSERT_TRUE(tree.get_table_entry(0, &tab, &index));
    EXPECT_TRUE(tab->check_mark(RA_MARK_PRESENT, index));
    ASSERT_EQ(0, tree.store(1, 0));
    EXPECT_FALSE(tab->check_mark(RA_MARK_PRESENT, 1));
    EXPECT_TRUE(upper_level->check_mark(RA_MARK_PRESENT, 0));

    // Now clear the last entry, we should expect the mark to clear now
    ASSERT_EQ(0, tree.store(0, 0));
    EXPECT_FALSE(upper_level->check_mark(RA_MARK_PRESENT, 0));
    EXPECT_TRUE(upper_level->mark_empty(RA_MARK_PRESENT));
}

TEST(radix, mark_traversal)
{
    // Test that traversing a radix tree based on marks works properly.
    radix_tree tree;
    tree.store(0, 0x100);
    tree.store(10, 0x100100);
    tree.store(0x401, 0x10000);
    tree.store(0xffffffffffffffff, 0x10000);

    auto out0 = tree.get(10);
    auto out1 = tree.get(0x401);
    auto out2 = tree.get(0xffffffffffffffff);
    ASSERT_TRUE(out0.has_value());
    ASSERT_TRUE(out1.has_value());
    ASSERT_TRUE(out2.has_value());

    tree.set_mark(10, RA_MARK_0);
    tree.set_mark(0xffffffffffffffff, RA_MARK_0);
    tree.set_mark(0, RA_MARK_1);

    auto cursor = radix_tree::cursor::from_range_on_marks(&tree, RA_MARK_0, 0);

    ASSERT_FALSE(cursor.is_end());
    ASSERT_EQ(10ul, cursor.current_idx());
    ASSERT_EQ(0x100100ul, cursor.get());
    cursor.advance();
    ASSERT_FALSE(cursor.is_end());
    ASSERT_EQ(0xfffffffffffffffful, cursor.current_idx());
    ASSERT_EQ(0x10000ul, cursor.get());
    cursor.advance();
    ASSERT_TRUE(cursor.is_end());

    // Clear all entries with mark 0 and check that the iterator is empty
    tree.store(10, 0);
    tree.store(0xffffffffffffffff, 0);

    cursor = radix_tree::cursor::from_range_on_marks(&tree, RA_MARK_0, 0);

    ASSERT_TRUE(cursor.is_end());
}

TEST(radix, set_mark_clear_mark_works)
{
    radix_tree tree;
    tree.store(0, 0x100);
    tree.store(10, 0x100100);
    tree.store(0x401, 0x10000);
    tree.store(0xffffffffffffffff, 0x10000);

    tree.set_mark(10, RA_MARK_0);
    auto cursor = radix_tree::cursor::from_range_on_marks(&tree, RA_MARK_0, 0);

    ASSERT_FALSE(cursor.is_end());
    tree.clear_mark(10, RA_MARK_0);
    cursor = radix_tree::cursor::from_range_on_marks(&tree, RA_MARK_0, 0);

    ASSERT_TRUE(cursor.is_end());
}

TEST(radix, copy_tags_works)
{
    // Let's test if the present tagging works and is getting copied when copying trees.
    // I caught this after a month and a half because I forgot to run kernel_api_tests...
    // Forked vm objects (that use radix trees to store pages) would show up as empty and would
    // re-fault a new page, which subsequently broke fork-heavy programs (like kernel_api_tests,
    // that abuses them for many tests that need clean slates). To test these properties, we snoop
    // the marks array in each node.

    radix_tree tree;

    // Test 1: Entry at the first level
    ASSERT_EQ(0, tree.store(1, 0x100));

    radix_tree_node *tab;
    unsigned int index;
    ASSERT_TRUE(tree.get_table_entry(1, &tab, &index));
    ASSERT_TRUE(tab->check_mark(RA_MARK_PRESENT, index));

    // Now let's force a second level to appear. Note that the top level should have the mark set as
    // well now, even after expanding the tree.
    ASSERT_EQ(0, tree.store(radix::rt_nr_entries, 0x100));
    ASSERT_NONNULL(tab->parent);
    EXPECT_TRUE(tab->parent->check_mark(RA_MARK_PRESENT, tab->offset));

    // Now check the radix::rt_nr_entries's present, plus the upper level too
    ASSERT_TRUE(tree.get_table_entry(radix::rt_nr_entries, &tab, &index));
    EXPECT_TRUE(tab->check_mark(RA_MARK_PRESENT, index));
    EXPECT_TRUE(tab->parent->check_mark(RA_MARK_PRESENT, tab->offset));

    radix_tree tree2 =
        tree.copy([](unsigned long val, void *ctx) -> unsigned long { return val; }, nullptr)
            .unwrap();

    ASSERT_TRUE(tree.get_table_entry(radix::rt_nr_entries, &tab, &index));
    EXPECT_TRUE(tab->check_mark(RA_MARK_PRESENT, index));
    EXPECT_TRUE(tab->parent->check_mark(RA_MARK_PRESENT, tab->offset));
}

#endif
