/*
 * Copyright (c) 2022 Pedro Falcato
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
#include <onyx/types.h>
#include <onyx/vm.h>

#include <onyx/expected.hpp>

#undef RADIX_TREE_DEBUG
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

constexpr size_t max_order = 7;
constexpr size_t nr_entries = 512;

class radix_tree
{
    int order{0};
    unsigned long *tree{nullptr};

    int grow_radix_tree(int order);

    class cursor
    {
        radix_tree *tree_;
        unsigned long path_[max_order];

        cursor(radix_tree *tree);
    };

    /**
     * @brief Clear a level of the radix tree
     * Note: Invokes itself recursively
     *
     * @param level Level (L0 is the base, Lorder-1 is the max)
     */
    void clear_level(int level, unsigned long *table);

    unsigned long *allocate_table();

public:
    radix_tree() = default;

    ~radix_tree();

    int store(unsigned long index, unsigned long value);
    expected<unsigned long, int> get(unsigned long index);

    void clear();
};

unsigned long *radix_tree::allocate_table()
{
    return (unsigned long *) zalloc(PAGE_SIZE);
}

int radix_tree::grow_radix_tree(int to_order)
{
    int order_diff = to_order - order;

    for (int i = 0; i < order_diff; i++)
    {
        unsigned long *table = allocate_table();
        if (!table)
            return -ENOMEM;
        table[0] = (unsigned long) tree;
        tree = table;
        order++;
    }

    return 0;
}

int radix_tree::store(unsigned long index, unsigned long value)
{
    static_assert(PAGE_SIZE == 4096, "Radix calculations currently only work for PAGE_SIZE = 4096 "
                                     "due to tables being page-sized");
    unsigned int indices[max_order];

    for (unsigned int i = 0; i < max_order; i++)
    {
        indices[i] = (index >> (i * 9)) & 0x1ff;
    }

    DPRINTF("indices: ");

    int max_order_set = 0;

    for (unsigned int i = 0; i < max_order; i++)
    {
        DPRINTF("%u ", indices[i]);

        if (indices[i])
            max_order_set = i + 1;
    }

    DPRINTF("\n");

    DPRINTF("This requires an order %u\n", max_order_set);

    if (order < max_order_set)
    {
        if (grow_radix_tree(max_order_set) < 0)
            return -ENOMEM;
    }

    unsigned long *tab = tree;

    for (unsigned int i = order - 1; i != 0; i--)
    {
        DPRINTF("Going to index %u\n", indices[i]);
        auto index = indices[i];
        unsigned long entry = tab[index];
        if (!entry)
        {
            tab[index] = (unsigned long) allocate_table();
            if (!tab[index])
                return -ENOMEM;
            entry = tab[index];
        }
        tab = (unsigned long *) entry;
    }

    tab[indices[0]] = value;

    return 0;
}

expected<unsigned long, int> radix_tree::get(unsigned long index)
{
    static_assert(PAGE_SIZE == 4096, "Radix calculations currently only work for PAGE_SIZE = 4096 "
                                     "due to tables being page-sized");
    unsigned int indices[max_order];

    for (unsigned int i = 0; i < max_order; i++)
    {
        indices[i] = (index >> (i * 9)) & 0x1ff;
    }

    int max_order_set = 0;

    for (unsigned int i = 0; i < max_order; i++)
    {
        DPRINTF("%u ", indices[i]);

        if (indices[i])
            max_order_set = i + 1;
    }

    if (max_order_set > order)
        return unexpected{-ENOENT};

    unsigned long *tab = tree;

    for (unsigned int i = order - 1; i != 0; i--)
    {
        auto index = indices[i];
        unsigned long entry = tab[index];
        DPRINTF("Going to index %u\n", indices[i]);
        if (!entry)
        {
            return unexpected{-ENOENT};
        }

        tab = (unsigned long *) entry;
    }

    const auto val = tab[indices[0]];

    if (!val)
        return unexpected{-ENOENT};
    return val;
}

/**
 * @brief Clear a level of the radix tree
 * Note: Invokes itself recursively
 *
 * @param level Level (L0 is the base, Lorder-1 is the max)
 */
void radix_tree::clear_level(int level, unsigned long *table)
{
    for (size_t i = 0; i < nr_entries; i++)
    {
        auto entry = table[i];

        if (!entry)
            continue;
        if (level != order - 1)
        {
            DPRINTF("Deleting L%u table %lx\n", level + 1, entry);
            clear_level(level + 1, (unsigned long *) entry);
        }
        else
        {
            DPRINTF("Deleting value entry %lx (table %p index %zu)\n", entry, table, i);
        }

        table[i] = 0;
    }

    free(table);
}

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

#endif
