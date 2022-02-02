/*
 * Copyright (c) 2020 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 */
#ifndef _CARBON_RBTREE_ITER_HPP
#define _CARBON_RBTREE_ITER_HPP

class rb_tree_iterator
{
private:
    friend class rb_tree;
    rb_node<Key, T>* current_node;
    rb_tree_iterator(rb_tree<Key, T>* t)
    {
        current_node = t->min();
    }

    rb_tree_iterator(rb_node<Key, T>* n) : current_node{n}
    {
    }

public:
    rb_tree_iterator() : current_node{nullptr}
    {
    }
    rb_tree_iterator(const rb_tree_iterator& rhs) = default;
    ~rb_tree_iterator() = default;
    rb_tree_iterator(rb_tree_iterator&& rhs) = default;
    rb_tree_iterator& operator=(rb_tree_iterator&& rhs) = default;
    rb_tree_iterator& operator=(const rb_tree_iterator& rhs) = default;

    T& operator*()
    {
        return current_node->data;
    }

    bool operator==(const rb_tree_iterator& rhs) const
    {
        return current_node == rhs.current_node;
    }

    bool operator!=(const rb_tree_iterator& rhs) const
    {
        return current_node != rhs.current_node;
    }

    rb_tree_iterator& operator++()
    {
        /* Prefix increment */
        current_node = current_node->next();
        return *this;
    }

    rb_tree_iterator& operator++(int)
    {
        /* Postfix increment */
        rb_tree_iterator it(*this);
        operator++();
        return it;
    }

    rb_tree_iterator& operator--()
    {
        /* Prefix increment */
        current_node = current_node->prev();
        return *this;
    }

    rb_tree_iterator& operator--(int)
    {
        /* Postfix increment */
        rb_tree_iterator it(*this);
        operator--();
        return it;
    }
};

#endif
