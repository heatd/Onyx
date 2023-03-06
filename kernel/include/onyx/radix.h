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

#include <onyx/expected.hpp>

constexpr size_t max_order = 7;
constexpr size_t nr_entries = 512;

using rt_entry_t = unsigned long;

class radix_tree
{
public:
    using copy_cb_t = unsigned long (*)(unsigned long entry, void *ctx);

private:
    int order{0};
    rt_entry_t *tree{nullptr};

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
     * @param table Table to clear
     */
    void clear_level(int level, rt_entry_t *table);

    rt_entry_t *allocate_table();

    /**
     * @brief Copy a radix tree level
     *
     * @param level Level (L0 is the base, Lorder-1 is the max)
     * @param table Original table
     * @param cb Callback for entry copying
     * @param ctx Context for entry copying's callback
     * @return Expected containing new table, or negative error code
     */
    expected<rt_entry_t *, int> copy_level(int level, const rt_entry_t *table, copy_cb_t cb,
                                           void *ctx);

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

    template <typename Callable>
    bool for_every_entry_internal(int order, Callable c)
    {
        unsigned int
    }

    template <typename Callable>
    bool for_every_entry(Callable c)
    {
        return for_every_internal(order - 1, c);
    }
};

#endif
