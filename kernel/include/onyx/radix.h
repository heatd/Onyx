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
#include <onyx/compiler.h>

#ifndef __cplusplus
#error "We (still) need C++ for radix"
#endif

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
constexpr size_t nr_marks = 5;

} // namespace radix

/* We can have marks, and mark entries as such. These marks get propagated up the tree, such that we
 * can efficiently search for such entries. We also have a special mark called PRESENT, hidden from
 * users, that lets us easily search the tree for present entries.
 */
#define RA_MARK_0       0
#define RA_MARK_1       1
#define RA_MARK_2       2
#define RA_MARK_3       3
#define RA_MARK_PRESENT 4

using radix::rt_entry_t;

struct radix_tree_node
{
    static constexpr unsigned int marks_nr_entries =
        radix::rt_nr_entries / sizeof(unsigned long) / 8;

    rt_entry_t entries[radix::rt_nr_entries];
    struct radix_tree_node *parent;
    unsigned long offset;
    unsigned long marks[radix::nr_marks][marks_nr_entries];

    bool mark_empty(unsigned int mark);
    __attribute__((always_inline)) inline bool check_mark(unsigned int mark, unsigned int entry)
    {
        constexpr unsigned int bpw = sizeof(unsigned long) * 8;
        return marks[mark][entry / bpw] & (1UL << (entry % bpw));
    }
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

    /**
     * @brief Given a table and the index in that table, propagate a tag up the tree
     *
     * @param table Tree node
     * @param tabindex Index in the table
     * @param mark Mark to propagate
     * @param set True if we should set, else unset
     */
    static void propagate_tag(radix_tree_node *table, unsigned int tabindex, unsigned int mark,
                              bool set);

    /**
     * @brief Given a table and the index in that table, clear the tags and propagate them up the
     * tree.
     * Supposed to be used when clearing entries.
     *
     * @param table Tree node
     * @param tabindex Index in the table
     */
    static void clear_all_tags(radix_tree_node *table, unsigned int tabindex);

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
     * @brief Exchange a value to an index
     *
     * @param index Index to store to
     * @param value Value to store
     * @return Old value on success, negative error codes
     */
    unsigned long xchg(unsigned long index, rt_entry_t value);

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
        unsigned int mark{RA_MARK_PRESENT};

        cursor(radix_tree *tree, unsigned long end = -1ul) : tree_{tree}, end{end}
        {
        }

        /**
         * @brief Find the next index to the given mark
         *
         * @return Next index. If not found, returns radix::nr_entries.
         */
        unsigned int find_next_index();

        /**
         * @brief Move the index to the next valid one
         *
         */
        void move_index();

    public:
        static cursor from_range_on_marks(radix_tree *tree, unsigned int mark, unsigned long start,
                                          unsigned long end = -1ul);

        static cursor from_range(radix_tree *tree, unsigned long start, unsigned long end = -1ul)
        {
            return from_range_on_marks(tree, RA_MARK_PRESENT, start, end);
        }

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

    /**
     * @brief Set a mark on an index
     *
     * @param index Index to mark
     * @param mark The mark to set
     */
    void set_mark(unsigned long index, unsigned int mark);

    // TODO(pedro): Should get_table_entry be private?
    /**
     * @brief Get the table entry for a given index
     *
     * @param index Radix tree index
     * @param table Pointer to a pointer to a table. Gets filled on success.
     * @param tabindex Pointer to a table index. Gets filled on success
     * @return True if we got the entry, else false.
     */
    bool get_table_entry(unsigned long index, radix_tree_node **table, unsigned int *tabindex);

    /**
     * @brief Clear a mark on an index
     *
     * @param index Index to mark
     * @param mark The mark to clear
     */
    void clear_mark(unsigned long index, unsigned int mark);

    /**
     * @brief Check if a given mark is set (in the whole tree)
     *
     * @param mark Mark to check
     * @return True if set, else false
     */
    bool mark_is_set(unsigned int mark)
    {
        if (!tree)
            return false;
        return !tree->mark_empty(mark);
    }
};

static inline bool radix_err(unsigned long ret)
{
    return ret >= -4096UL;
}

#endif
