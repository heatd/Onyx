/*
 * Copyright (c) 2019 LK Trusty Authors. All Rights Reserved.
 * Copyright (c) 2023 Pedro Falcato
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files
 * (the "Software"), to deal in the Software without restriction,
 * including without limitation the rights to use, copy, modify, merge,
 * publish, distribute, sublicense, and/or sell copies of the Software,
 * and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
#ifndef _ONYX_LIB_BST_H
#define _ONYX_LIB_BST_H

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>

#include <onyx/compiler.h>
#include <onyx/utils.h>

/*
 * lk defines DEBUG_ASSERT for debug build asserts. Enable those checks for
 * host test as well.
 */
#ifndef DEBUG_ASSERT
#define DEBUG_ASSERT(e) assert(e)
#endif

/**
 * struct bst_node - Node in binary search tree.
 * @rank:   Rank value used for rebalancing. 0 indicates node is not in a tree.
 * @parent: Pointer to parent node or %NULL for root node.
 * @child:  Array of pointers to child nodes. @child[0] points to the left child
 *          and @child[1] points to the right child.
 */
struct bst_node {
    size_t rank;
    struct bst_node *parent;
    struct bst_node *child[2];
};

struct bst_root {
    struct bst_node *root;
};

struct bst_augmented_ops {
    void (*rotate)(struct bst_node *old_root, struct bst_node *new_root);
    void (*copy)(struct bst_node *old, struct bst_node *new_);
    void (*propagate)(struct bst_node *cur, struct bst_node *stop);
};

#define BST_AUGMENTED(name, structname, field, augmentedtype, augmentedfield, compute) \
    static inline void name##_propagate(struct bst_node *cur, struct bst_node *stop)   \
    {                                                                                  \
        while (cur != stop)                                                            \
        {                                                                              \
            structname *node = container_of(cur, structname, field);                   \
            augmentedtype aug = compute(node);                                         \
            if (aug == node->augmentedfield)                                           \
                break;                                                                 \
            node->augmentedfield = aug;                                                \
            cur = cur->parent;                                                         \
        }                                                                              \
    }                                                                                  \
    static const struct bst_augmented_ops name = {                                     \
        .rotate = NULL, .copy = NULL, .propagate = name##_propagate}



#ifdef __cplusplus
extern "C" {
#endif

#define BST_NODE_INITIAL_VALUE {0, NULL, {NULL, NULL}}
#define BST_ROOT_INITIAL_VALUE {NULL}

#ifdef __cplusplus
#define CONSTEXPR constexpr
#else
#define CONSTEXPR
#endif

CONSTEXPR
static inline void bst_node_initialize(struct bst_node *node) {
    /* Set rank to an invalid value to detect double insertion. */
    node->rank = 0;
}

CONSTEXPR
static inline void bst_root_initialize(struct bst_root *root) {
    root->root = NULL;
}

/**
 * bst_compare_t - Compare function provided by caller
 * @a: First node to compare
 * @b: Second node to compare
 *
 * Return: a positive number if @b should be after @a, 0 if @b is a match for
 * @a, a negative otherwise.
 */
typedef int (*bst_compare_t)(struct bst_node *a, struct bst_node *b);

/**
 * bst_search - Find a node in a binary search tree.
 * @root:       Tree to search
 * @node:       Dummy node containing key to search for.
 * @compare:    Compare function.
 *
 * Find a node in a binary search tree. Use bst_search_type instead to get a
 * pointer to the struct that contains @node.
 *
 * Note that if there are multiple matching nodes in the tree, the node returned
 * may not be the leftmost matching node.
 *
 * Return: Node in @root matching @node, or %NULL if no matching node is found.
 */
static inline struct bst_node *bst_search(const struct bst_root *root,
                                          struct bst_node *node,
                                          bst_compare_t compare) {
    DEBUG_ASSERT(root);
    DEBUG_ASSERT(node);
    DEBUG_ASSERT(compare);

    struct bst_node *tree_node = root->root;
    while (tree_node) {
        int cmp = compare(tree_node, node);
        if (!cmp) {
            return tree_node;
        }
        tree_node = tree_node->child[cmp > 0];
    }
    return NULL;
}

/**
 * bst_search - Find an item in a binary search tree.
 * @root:       Tree to search
 * @item:       Dummy item containing key to search for.
 * @compare:    Compare function.
 * @type:       Type of @item.
 * @member:     Name of struct bst_node embedded in @type.
 *
 * Return: Item in @root matching @item, or %NULL if no matching node is found.
 */
#define bst_search_type(root, item, compare, type, member) \
    containerof_null_safe(bst_search(root, &(item)->member, compare), type, \
                          member)

/* Internal helper. Don't call directly */
void bst_update_rank_insert(struct bst_root *root, struct bst_node *node,
                            const struct bst_augmented_ops *augmentcb);

/**
 * @brief Link a node to the tree
 * This function does not update the rank after insertion, please call bst_update_rank_insert.
 * 
 * @param nodep Where to link to (pointer to pointer)
 * @param parent Parent (if NULL, this is the root node)
 * @param child Node we're linking
 */
__always_inline void bst_link(struct bst_node **nodep, struct bst_node *parent,
                              struct bst_node *child)
{
    DEBUG_ASSERT(*nodep == NULL);
    child->rank = 1;
    child->parent = parent;
    child->child[0] = child->child[1] = NULL;
    *nodep = child;
    /* Note: We do not update the rank here */
}

/**
 * bst_insert_augmented - Insert node in tree.
 * @root:       Tree.
 * @node:       Node to insert.
 * @compare:    Compare function.
 * @augmentcb:  Augmented callbacks (for node rotation)
 *
 * Insert @node in @root.
 * @node will already have its augmented information filled in before getting
 * linked, hence @augmentcb is only needed for rotation.
 *
 * Return: %true if @node was inserted. %false if a node matching @node is
 * already in @root.
 */
static inline bool bst_insert_augmented(struct bst_root *root, struct bst_node *node,
                              bst_compare_t compare,
                              const struct bst_augmented_ops *augmentcb) {
    DEBUG_ASSERT(root);
    DEBUG_ASSERT(node);
    DEBUG_ASSERT(compare);
    DEBUG_ASSERT(!node->rank);

    struct bst_node *parent = NULL;
    struct bst_node **parent_ptr = &root->root;
    int diff;
    bool is_right_child = false;
    while (true) {
        struct bst_node *tree_node = *parent_ptr;
        if (!tree_node) {
            bst_link(parent_ptr, parent, node);
            bst_update_rank_insert(root, node, augmentcb);
            return true;
        }
        diff = compare(tree_node, node);
        if (!diff) {
            return false;
        }
        is_right_child = diff > 0;
        parent_ptr = &tree_node->child[is_right_child];
        parent = tree_node;
    }
}

/**
 * bst_insert - Insert node in tree.
 * @root:       Tree.
 * @node:       Node to insert.
 * @compare:    Compare function.
 *
 * Insert @node in @root.
 *
 * Return: %true if @node was inserted. %false if a node matching @node is
 * already in @root.
 */
__always_inline bool bst_insert(struct bst_root *root, struct bst_node *node,
                              bst_compare_t compare)
{
    return bst_insert_augmented(root, node, compare, NULL);
}

/**
 * bst_delete - Remove node from tree.
 * @root:       Tree.
 * @node:       Node to delete
 * @augmentcb:  Augment callbacks for deletion.
 *
 * Delete @node from @root.
 */
void bst_delete_augmented(struct bst_root *root, struct bst_node *node,
                          const struct bst_augmented_ops *augmentcb);

/**
 * bst_delete - Remove node from tree.
 * @root:   Tree.
 * @node:   Node to delete
 *
 * Delete @node from @root.
 */
__always_inline void bst_delete(struct bst_root *root, struct bst_node *node)
{
    bst_delete_augmented(root, node, NULL);
}

/**
 * bst_prev - Get previous node.
 * @root:       Tree.
 * @node:       Node to move from.
 *
 * Use bst_prev_type instead to use pointers to the struct that contains @node.
 *
 * Return: If @node is %NULL, right-most node in @root.
 *         If @node is not %NULL, right-most node to the left of @node.
 *         %NULL if the node described above does not exist.
 */
struct bst_node *bst_prev(struct bst_root *root, struct bst_node *node);

/**
 * bst_prev_type - Get previous item.
 * @root:       Tree.
 * @item:       Item to move from.
 * @type:       Type of @item.
 * @member:     Name of struct bst_node embedded in @type.
 *
 * Return: If @item is %NULL, right-most item in @root.
 *         If @item is not %NULL, right-most item to the left of @item.
 *         %NULL if the item described above does not exist.
 */
#define bst_prev_type(root, item, type, member) \
    containerof_null_safe(bst_prev(root, item), type, member)

/**
 * bst_next - Get next node.
 * @root:       Tree.
 * @node:       Node to move from.
 *
 * Use bst_next_type instead to use pointers to the struct that contains @node.
 *
 * Return: If @node is %NULL, left-most node in @root.
 *         If @node is not %NULL, left-most node to the right of @node.
 *         %NULL if the node described above does not exist.
 */
struct bst_node *bst_next(const struct bst_root *root, struct bst_node *node);

/**
 * bst_next_type - Get previous item.
 * @root:       Tree.
 * @item:       Item to move from.
 * @type:       Type of @item.
 * @member:     Name of struct bst_node embedded in @type.
 *
 * Return: If @item is %NULL, left-most item in @root.
 *         If @item is not %NULL, left-most item to the right of @item.
 *         %NULL if the item described above does not exist.
 */
#define bst_next_type(root, item, type, member) \
    containerof_null_safe(bst_next(root, item), type, member)

/**
 * bst_for_every_entry - Loop over every entry in a tree.
 * @root:       Tree.
 * @entry:      Entry variable used by loop body.
 * @type:       Type of @entry.
 * @member:     Name of struct bst_node embedded in @type.
 *
 * Loop over every node in @root, convert that node to @type and provide it as
 * @entry to the loop body directly following this macro.
 *
 * It is safe to delete @entry from @root in the body if the loop, but it is not
 * safe to delete any other nodes or insert any nodes.
 */
#define bst_for_every_entry(root, entry, type, member) \
    for (struct bst_node *_bst_for_every_cursor = bst_next(root, NULL); \
            (_bst_for_every_cursor != NULL) && \
            ((entry) = container_of(_bst_for_every_cursor, type, member)) && \
            ((_bst_for_every_cursor = bst_next(root, _bst_for_every_cursor)) \
             || true);)

/* Internal helper. Don't call directly */
void bst_delete_all_helper(struct bst_root *root, struct bst_node *node);

/**
 * bst_for_every_entry_delete - Loop over tree and delete every entry.
 * @root:       Tree.
 * @entry:      Entry variable used by loop body.
 * @type:       Type of @entry.
 * @member:     Name of struct bst_node embedded in @type.
 *
 * Loop over every node in @root, convert that node to @type and provide it as
 * @entry to the loop body directly following this macro.
 *
 * @entry will be removed from @root before entering the loop bode. It is not
 * safe to delete any other nodes or insert any nodes.
 */
#define bst_for_every_entry_delete(root, entry, type, member) \
    for (struct bst_node *_bst_for_every_cursor = bst_next(root, NULL); \
            (_bst_for_every_cursor != NULL) && ({\
            (entry) = container_of(_bst_for_every_cursor, type, member); \
            _bst_for_every_cursor = bst_next(root, _bst_for_every_cursor); \
            bst_delete_all_helper(root, &(entry)->member); true;});)

struct bst_node *bst_min(struct bst_root *root, struct bst_node *node);
 
static inline void bst_replace_node(struct bst_root *root, struct bst_node *old, struct bst_node *new_)
{
    struct bst_node *parent, *child;
    /* First adjust children, then parent, then parent's child */
    for (int i = 0; i < 2; i++)
    {
        child = old->child[i];
        if (child)
            child->parent = new_;
        new_->child[i] = child;
    }

    parent = old->parent;
    new_->parent = parent;

    if (parent)
        parent->child[parent->child[1] == old] = new_;
    else
        root->root = new_;
    new_->rank = old->rank;
}

static inline bool bst_root_empty(struct bst_root *root)
{
    return !root->root;
}

#ifdef __cplusplus
}
#endif
#endif
