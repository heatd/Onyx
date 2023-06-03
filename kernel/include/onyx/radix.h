/*
 * Copyright (c) 2022 - 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef _ONYX_RADIX_H
#define _ONYX_RADIX_H

#include <stddef.h>

#include <onyx/assert.h>

#include <onyx/expected.hpp>

namespace radix
{

using rt_entry_t = unsigned long;
/* nr_entries must be a power of 2, max_order must be log2(nr_entries) rounded up to the next
 * integer.
 */
constexpr size_t rt_nr_entries = 64;
constexpr size_t rt_entry_shift = 6;
constexpr size_t rt_entry_mask = rt_nr_entries - 1;
constexpr size_t rt_max_order = 11;

} // namespace radix

using radix::rt_entry_t;

struct radix_tree_node
{
    rt_entry_t entries[radix::rt_nr_entries];
    struct radix_tree_node *parent;
};

class radix_tree
{
public:
    using copy_cb_t = unsigned long (*)(unsigned long entry, void *ctx);

private:
    radix_tree_node *tree{nullptr};
    int order{0};

    int grow_radix_tree(int order);

    /**
     * @brief Clear a level of the radix tree
     * Note: Invokes itself recursively
     *
     * @param level Level (L0 is the base, Lorder-1 is the max)
     * @param table Table to clear
     */
    void clear_level(int level, radix_tree_node *table);

    radix_tree_node *allocate_table();

    /**
     * @brief Copy a radix tree level
     *
     * @param level Level (L0 is the base, Lorder-1 is the max)
     * @param table Original table
     * @param cb Callback for entry copying
     * @param ctx Context for entry copying's callback
     * @return Expected containing new table, or negative error code
     */
    expected<radix_tree_node *, int> copy_level(int level, const radix_tree_node *table,
                                                copy_cb_t cb, void *ctx);

public:
    radix_tree() = default;

    ~radix_tree();

    radix_tree &operator=(radix_tree &&rhs)
    {
        if (&rhs == this)
            return *this;

        if (tree)
            clear();

        order = rhs.order;
        tree = rhs.tree;

        rhs.tree = nullptr;

        return *this;
    }

    radix_tree(radix_tree &&rhs)
    {
        if (&rhs == this)
            return;

        order = rhs.order;
        tree = rhs.tree;

        rhs.tree = nullptr;
    }

    // Explicitly disallow copy

    radix_tree(const radix_tree &) = delete;

    radix_tree &operator=(const radix_tree &) = delete;

    /**
     * @brief Store a value to an index
     *
     * @param index Index to store to
     * @param value Value to store
     * @return 0 on success, negative error codes
     */
    int store(unsigned long index, rt_entry_t value);

    /**
     * @brief Fetch a value
     *
     * @param index  Index to fetch from
     * @return Expected with the value, or negative error codes
     */
    expected<rt_entry_t, int> get(unsigned long index);

    /**
     * @brief Clear a radix tree
     *
     */
    void clear();

    /**
     * @brief Create a copy of a radix tree
     *
     * @param cb Callback called for entry copying
     * @param ctx Context for the copy callback
     * @return Expected containing the radix_tree, or error code.
     */
    expected<radix_tree, int> copy(copy_cb_t cb, void *ctx);

    class cursor
    {
        friend class radix_tree;
        radix_tree *tree_;
        radix_tree_node *current{nullptr};
        unsigned int current_index{0};
        unsigned long current_location{0};
        unsigned long end;
        int depth{0};

        cursor(radix_tree *tree, unsigned long end = -1ul) : tree_{tree}, end{end}
        {
        }

        void go_up_and_down();

        bool try_go_down(radix_tree_node *node, int depth);

    public:
        static cursor from_range(radix_tree *tree, unsigned long start, unsigned long end = -1ul);

        static cursor from_index(radix_tree *tree, unsigned long index = 0)
        {
            return from_range(tree, index);
        }

        bool is_end() const
        {
            return current == nullptr;
        }

        void advance();

        rt_entry_t get()
        {
            return current->entries[current_index];
        }

        unsigned long current_idx() const
        {
            return current_location;
        }

        void store(rt_entry_t new_val);
    };

    template <typename Callable>
    bool for_every_entry(Callable c)
    {
        cursor cur = cursor::from_range(this, 0);
        while (!cur.is_end())
        {
            auto entry = cur.get();
            auto index = cur.current_idx();
            if (!c(entry, index))
                return false;
            cur.advance();
        }

        return true;
    }
};

#endif
