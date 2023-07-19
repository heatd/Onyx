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
#include <lib/binary_search_tree.h>

/**
 * bst_node_rank - Internal helper function
 * @node:   Node to check.
 *
 * Return: Rank of @node or 0 if @node is %NULL.
 */
static size_t bst_node_rank(struct bst_node *node) {
    return node ? node->rank : 0;
}

/**
 * bst_is_right_child - Internal helper function
 * @node:   Node to check.
 *
 * Return: %true if @node is the right child of @node->parent. %false if
 *         @node->parent is %NULL or if @node is the left child of
 *         @node->parent.
 */
static bool bst_is_right_child(struct bst_node *node) {
    DEBUG_ASSERT(node);
    DEBUG_ASSERT(!node->parent || node->parent->child[0] == node ||
                 node->parent->child[1] == node);
    return node->parent && node->parent->child[1] == node;
}

/**
 * bst_parent_ptr - Internal helper function
 * @root:   Tree.
 * @node:   Node in @root.
 *
 * Return: Pointer where @node is linked in the tree. If @node is the root node
 * this is &root->root, otherwise it is the address of child pointer in the
 * parent node of @node that points to @node.
 */
static struct bst_node **bst_parent_ptr(struct bst_root *root,
                                        struct bst_node *node) {
    DEBUG_ASSERT(root);
    DEBUG_ASSERT(node);
    struct bst_node **parent_ptr = node->parent ?
        &node->parent->child[bst_is_right_child(node)] : &root->root;
    DEBUG_ASSERT(*parent_ptr == node);
    return parent_ptr;
}

/**
 * bst_link_node - Internal helper function
 * @parent:         Target node.
 * @is_right_child: Index of child to set.
 * @child:          New child node.
 *
 * Set child node in @parent. If @child is not %NULL, update it to point to
 * @parent.
 */
static void bst_link_node(struct bst_node *parent,
                          bool is_right_child,
                          struct bst_node *child) {
    parent->child[is_right_child] = child;
    if (child) {
        child->parent = parent;
    }
}

/**
 * bst_move_node - Internal helper function
 * @root:       Tree.
 * @old_node:   Node to unlink.
 * @new_node:   Node to link where @old_node was.
 *
 * Replace node in @root at @old_node with @new_node.
 */
static void bst_move_node(struct bst_root *root,
                          struct bst_node *old_node,
                          struct bst_node *new_node) {
    DEBUG_ASSERT(root);
    DEBUG_ASSERT(old_node);
    *bst_parent_ptr(root, old_node) = new_node;
    if (new_node) {
        new_node->parent = old_node->parent;
    }
    old_node->parent = NULL;
}

/**
 * bst_rotate - Internal helper function
 * @root:               Tree.
 * @up:                 Node to move up.
 * @down:               Node to move down.
 * @up_was_right_child: %true if @up was the right child of @down.
 * @augmentcb:          Augmented ops for rotation.
 *
 * Swap nodes @up and @down (pictured for up_was_right_child==false):
 *
 *         down           up
 *        /    \         /  \
 *       up     C       A    down
 *      /  \                /    \
 *     A    B              B      C
 *
 * Caller is responsible for updating the rank of the moved nodes.
 */
static void bst_rotate(struct bst_root *root, struct bst_node *up,
                       struct bst_node *down, bool up_was_right_child,
                       const struct bst_augmented_ops *augmentcb) {
    DEBUG_ASSERT(down->child[up_was_right_child] == up);
    struct bst_node *move_subtree = up->child[!up_was_right_child];
    struct bst_node *downp = down->parent;
    bst_move_node(root, down, up);
    bst_link_node(down, up_was_right_child, move_subtree);
    bst_link_node(up, !up_was_right_child, down);

    if (augmentcb) {
        /* re-augment every node that got things moved under it.
         * Logically, we can skip recalculating A, B and C themselves as their augment is similar. */
#if 0
        /* TODO: Figure out if a ->rotate() ish scheme can be used here like in rb trees */
        augmentcb->rotate(up, down); /* B used to be in up, now is in down */
        if (downp)
            augmentcb->rotate(downp, up); /* for the down node rotation */
#endif
        augmentcb->propagate(down, up);
        augmentcb->propagate(up, downp);
    }
}

/**
 * bst_rotate_insert - Internal helper function
 * @root:               Tree.
 * @up1:                Node to move up if a single rotate is enough.
 * @down:               Node to move down.
 * @up_was_right_child: %true if @up1 was the right child of @down.
 * @augmentcb:          Augmented BST ops to call on rotation (may be null)
 *
 * Rotate sub-tree (once or twice) after insert and update ranks.
 */
static void bst_rotate_insert(struct bst_root *root, struct bst_node *up1,
                              struct bst_node *down, bool up_was_right_child,
                              const struct bst_augmented_ops *augmentcb) {
    DEBUG_ASSERT(down->child[up_was_right_child] == up1);
    DEBUG_ASSERT(up1->rank == down->rank);
    DEBUG_ASSERT(down->rank >=
                 bst_node_rank(down->child[!up_was_right_child]) + 2);
    struct bst_node *up2 = up1->child[!up_was_right_child];
    if (bst_node_rank(up2) >= down->rank - 1) {
        DEBUG_ASSERT(bst_node_rank(up2) == down->rank - 1);
        /*
         * Swap nodes @up2 and @up1 then @up2 and @down
         * (pictured for up_was_right_child==false):
         *
         *         down              down            up2
         *        /    \            /    \          /   \
         *       up1    D         up2     D      up1     down
         *      /   \            /   \          /  \     /   \
         *     A    up2        up1    C        A    B   C     D
         *         /   \      /   \
         *        B     C    A     B
         */
        up2->rank++;
        DEBUG_ASSERT(up1->rank == up2->rank);
        bst_rotate(root, up2, up1, !up_was_right_child, augmentcb);
        up1->rank--;
        bst_rotate(root, up2, down, up_was_right_child, augmentcb);
        down->rank--;
    } else {
        /*
         * Swap nodes @up1 and @down (pictured for up_was_right_child==false):
         *
         *         down           up1
         *        /    \         /   \
         *       up1    C       A     down
         *      /   \                /    \
         *     A     B              B      C
         */
        bst_rotate(root, up1, down, up_was_right_child, augmentcb);
        down->rank--;
    }
}

/**
 * bst_update_rank_insert - Internal helper function
 * @root:           Tree.
 * @node:           Node to start scan at.
 *
 * Promote nodes and/or rotate sub-trees to make @root a valid WAVL tree again.
 */
void bst_update_rank_insert(struct bst_root *root, struct bst_node *node,
                            const struct bst_augmented_ops *augmentcb) {
    size_t rank;
    DEBUG_ASSERT(root);
    DEBUG_ASSERT(node);
    DEBUG_ASSERT(node->rank == 1); /* Inserted node must have rank 1 */
    while (node) {
        bool is_right_child = bst_is_right_child(node);
        /*
         * At this point the rank of @node is 1 greater than it was before the
         * insert.
         *
         * For the tree to be valid, the parent of any  node is allowed to a
         * rank 1 or 2 greater than its child nodes. Assuming the tree was valid
         * before the insert, the @node->parent currently has the same rank as
         * @node or it has a rank one grater than the rank of @node. Incremeting
         * the rank @node->parent to be 2 greater than the rank of @node would
         * be unnecessary as it could not have had that rank already. Leaving
         * the rank of @node->parent at the same rank as @node would result in
         * en invalid tree. That means that the rank of @node->parent should now
         * be 1 greater than the rank of @node (if that is possible).
         */
        rank = node->rank + 1;
        node = node->parent;
        if (!node || node->rank >= rank) {
            DEBUG_ASSERT(!node || node->rank == rank);
            /*
             * Stop updating if we have reached the root, or a node that already
             * has a rank greater than the node child node we inserted or
             * updated as the tree is now valid.
             */
            return;
        }
        DEBUG_ASSERT(node->rank + 1 == rank);
        if (bst_node_rank(node->child[!is_right_child]) + 2 < rank) {
            /*
             * Rank of @node cannot be incremented. This means it can be moved
             * down and demoted instead.
             *
             * The tree can be rotated as pictured below. (a is @node which
             * could not be promoted. Numbers are known relative ranks.)
             *
             * If rank of c is 2 less than the rank of a (b is inserted or
             * promoted node):
             *
             *         a2           b2
             *        /  \         /  \
             *       b2   D0  =>  A    a1
             *      /  \              /  \
             *     A    c0          c0    D0
             *         /  \        /  \
             *        B    C      B    C
             *
             * If rank of c is 1 less than the rank of a (b is promoted node, c
             * is inserted or promoted node):
             *         a2               a2            __c2__
             *        /  \             /  \          /      \
             *       b2   D0          c2   D0       b1       a1
             *      / \       =>     /  \     =>   /  \     /  \
             *     A0  c1           b1   C        A0   B   C    D0
             *        /  \         /  \
             *       B    C       A0   B
             */
            bst_rotate_insert(root, node->child[is_right_child], node,
                              is_right_child, augmentcb);
            return;
        }
        node->rank = rank;
    }
}

/**
 * bst_rotate_delete - Internal helper function
 * @root:               Tree.
 * @up1:                Node to move up if a single rotate is enough.
 * @down:               Node to move down.
 * @up_was_right_child: %true if @up1 was the right child of @down.
 * @augmentcb:          Augment cb for rotation
 *
 * Rotate sub-tree (once or twice) after delete and update ranks.
 */
static void bst_rotate_delete(struct bst_root *root, struct bst_node *up1,
                              struct bst_node *down, bool up_was_right_child,
                              const struct bst_augmented_ops *augmentcb) {
    DEBUG_ASSERT(down->child[up_was_right_child] == up1);
    DEBUG_ASSERT(up1->rank == down->rank - 1);
    DEBUG_ASSERT(down->rank ==
                 bst_node_rank(down->child[!up_was_right_child]) + 3);
    struct bst_node *up2 = up1->child[!up_was_right_child];
    if (bst_node_rank(up1->child[up_was_right_child]) <= down->rank - 3) {
        DEBUG_ASSERT(bst_node_rank(up2) == down->rank - 2);
        /*
         * Swap nodes @up2 and @up1 then @up2 and @down
         * (pictured for up_was_right_child==false):
         *
         *         down(0)              down            up2(0)
         *        /       \            /    \          /    \
         *       up1(-1)   D(-3)     up2     D      up1(-2)  down(-2)
         *      /       \            /   \          /  \     /   \
         *     A(-3)    up2(-2)    up1    C      A(-3)  B   C     D(-3)
         *              /   \     /   \
         *             B     C   A(-3) B
         */
        DEBUG_ASSERT(up1->rank == down->rank - 1);
        DEBUG_ASSERT(up2->rank == down->rank - 2);
        bst_rotate(root, up2, up1, !up_was_right_child, augmentcb);
        bst_rotate(root, up2, down, up_was_right_child, augmentcb);
        up2->rank += 2;
        up1->rank--;
        down->rank -= 2;
    } else {
        /*
         * Swap nodes @up1 and @down (pictured for up_was_right_child==false):
         *
         *         down(0)               up1(0)
         *        /       \             /      \
         *       up1(-1)   C(-3)       A(-2)    down(-1)
         *      /      \                       /        \
         *     A(-2)   B(-2/-3)               B(-2/-3)   C(-3)
         */
        bst_rotate(root, up1, down, up_was_right_child, augmentcb);
        up1->rank++;
        down->rank--;
        if (bst_node_rank(down->child[0]) == down->rank - 2 &&
            bst_node_rank(down->child[1]) == down->rank - 2) {
            /* Demote down if possible. (Required if down is a leaf node) */
            down->rank--;
        }
    }
}

/**
 * bst_update_rank_delete - Internal helper function
 * @root:           Tree.
 * @node:           Node to start scan at. This is the parent of the node that
 *                  was removed from the tree. Note that the removed node will
 *                  be a different node than the node passed to bst_delete if
 *                  that node had two children.
 * @is_right_child: %true if the right child of @node was deleted.
 *
 * Demote nodes and/or rotate sub-trees to make @root a valid WAVL tree again.
 */
static void bst_update_rank_delete(struct bst_root *root, struct bst_node *node,
                                   bool is_right_child,
                                   const struct bst_augmented_ops *augmentcb) {
    DEBUG_ASSERT(root);
    DEBUG_ASSERT(node);
    DEBUG_ASSERT(bst_node_rank(node->child[is_right_child]) <=
                 bst_node_rank(node->child[!is_right_child]));
    while (node) {
        DEBUG_ASSERT(node->rank > bst_node_rank(node->child[!is_right_child]));
        DEBUG_ASSERT(node->rank - 1 >
                     bst_node_rank(node->child[is_right_child]));
        DEBUG_ASSERT(node->rank <=
                     bst_node_rank(node->child[!is_right_child]) + 2);
        /*
         * At this point the rank of @node->child[is_right_child] has been
         * decremented. We may need to also decrement the rank of @node.
         */
        if (!node->child[0] && !node->child[1]) {
            /* Always demote leaf node (from 2 to 1) */
            /* We should not be in this function if the rank is alrady 1 */
            DEBUG_ASSERT(node->rank == 2);
        } else if (node->rank <=
                   bst_node_rank(node->child[is_right_child]) + 2) {
            /*
             * If rank of @node does not need to change then we now have a valid
             * tree.
             */
            return;
        }
        DEBUG_ASSERT(node->rank > 1);
        node->rank--;
        if (node->rank <= bst_node_rank(node->child[!is_right_child])) {
            /* We demoted @node, but it is now invalid on the other side */
            DEBUG_ASSERT(node->rank ==
                         bst_node_rank(node->child[!is_right_child]));
            if (bst_node_rank(node->child[!is_right_child]->child[0]) ==
                node->rank - 2 &&
                bst_node_rank(node->child[!is_right_child]->child[1]) ==
                node->rank - 2) {
                /* If the other child can be demoted, demote it and move up */
                node->child[!is_right_child]->rank--;
            } else {
                /*
                 * If the other child can not be demoted, rotate instead. This
                 * will produce a valid tree without changing the rank of the
                 * node linked at the current spot @node in the tree.
                 *
                 * Undo demotion as current bst_rotate_delete implemention
                 * assumes node rank is unchanged.
                 */
                node->rank++;
                bst_rotate_delete(root, node->child[!is_right_child], node,
                                  !is_right_child, augmentcb);
                return;
            }
        }
        is_right_child = bst_is_right_child(node);
        node = node->parent;
    }
}

/**
 * bst_find_edge - Internal helper function
 * @node:   Node to start search at.
 * @edge:   Direction if search.
 *
 * Return: leftmost (if @edge is %false) or rightmost (if @edge is %true) node
 * in subtree with @node as root.
 */
static struct bst_node *bst_find_edge(struct bst_node *node, bool edge) {
    struct bst_node *saved_node;
    DEBUG_ASSERT(node);
    do {
        saved_node = node;
        node = node->child[edge];
    } while (node);
    return saved_node;
}

/**
 * bst_delete_all_helper - Internal helper function
 * @root:   Tree.
 * @node:   Node to delete (most be the leftmost node in @root).
 *
 * Helper function to delete leftmost node in @root, assuming all other nodes
 * will be deleted next.
 */
void bst_delete_all_helper(struct bst_root *root, struct bst_node *node) {
    DEBUG_ASSERT(root);
    DEBUG_ASSERT(node);
    DEBUG_ASSERT(!node->child[0]);
    bst_move_node(root, node, node->child[1]);
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
                          const struct bst_augmented_ops *augmentcb) {
    DEBUG_ASSERT(root);
    DEBUG_ASSERT(node);
    struct bst_node *new_child;
    bool node_is_right_child = bst_is_right_child(node);
    struct bst_node *update_rank_start = node->parent;
    bool update_rank_is_right_child = node_is_right_child;
    if (!node->child[0]) {
        /*
         * If @node has no left child, link its right child in its place. (The
         * right child could be %NULL in this case)
         */
        new_child = node->child[1];
    } else if (!node->child[1]) {
        /*
         * If @node has no right child, link its left child in its place.
         */
        DEBUG_ASSERT(node->child[0]);
        new_child = node->child[0];
    } else {
        /*
         * If @node has both left and right children, delete (from the tree
         * structure point of view) the left-most node in the right sub-tree or
         * the right-most node in the left sub-tree instead. Either side would
         * work.
         */
        struct bst_node *edge_node = bst_find_edge(
                node->child[!node_is_right_child], node_is_right_child);
        struct bst_node *edge_child = edge_node->child[!node_is_right_child];
        update_rank_start = edge_node->parent;
        update_rank_is_right_child = bst_is_right_child(edge_node);
        if (update_rank_start == node) {
            update_rank_start = edge_node;
            update_rank_is_right_child = !node_is_right_child;
        }
        DEBUG_ASSERT(update_rank_start);
        bst_move_node(root, edge_node, edge_child);
        new_child = edge_node;
        DEBUG_ASSERT(new_child);
        bst_link_node(new_child, 0, node->child[0]);
        bst_link_node(new_child, 1, node->child[1]);
        if (augmentcb) {
            augmentcb->propagate(new_child, NULL);
            augmentcb->propagate(update_rank_start, NULL);
        }
        new_child->rank = node->rank;
    }

    struct bst_node *parent = node->parent;
    bst_move_node(root, node, new_child);

    if (augmentcb)
        augmentcb->propagate(parent, NULL);
    node->rank = 0;
    if (update_rank_start) {
        bst_update_rank_delete(root, update_rank_start, update_rank_is_right_child, augmentcb);
    }
}

/**
 * bst_prev_next - Internal helper function
 * @root:       Tree.
 * @node:       Node to move from.
 * @dir_next:   Directon to move.
 *
 * Return: If @node is %NULL and @dir_next is %false, right-most node in @root.
 *         If @node is %NULL and @dir_next is %true, left-most node in @root.
 *         If @node is not %NULL and @dir_next is %false, right-most node to the
 *         left of @node.
 *         If @node is not %NULL and @dir_next is %true, left-most node to the
 *         right of @node.
 *         %NULL if the node described above does not exist.
 */
static struct bst_node *bst_prev_next(const struct bst_root *root,
                                      struct bst_node *node,
                                      bool dir_next) {
    DEBUG_ASSERT(root);
    struct bst_node *next_child = node ? node->child[dir_next] : root->root;
    if (!node && !next_child) {
        return NULL; /* Empty tree */
    }
    /*
     * Comments below assume @dir_next is %true. For the @dir_next is %false
     * case, swap left and right.
     */
    if (next_child) {
        /* There is a right child, return the left-most node in that subtree */
        return bst_find_edge(next_child, !dir_next);
    } else {
        /* No right child, next node is the first right parent */
        struct bst_node *next_parent = node;
        while (bst_is_right_child(next_parent) == dir_next) {
            next_parent = next_parent->parent;
            if (!next_parent) {
                return NULL;
            }
        }
        return next_parent->parent;
    }
}

struct bst_node *bst_prev(struct bst_root *root, struct bst_node *node) {
    return bst_prev_next(root, node, false);
}

struct bst_node *bst_next(const struct bst_root *root, struct bst_node *node) {
    return bst_prev_next(root, node, true);
}

struct bst_node *bst_min(struct bst_root *root, struct bst_node *node)
{
    struct bst_node *c = node ?: root->root;
    if (!c)
        return NULL;
    return bst_find_edge(c, false);
}
