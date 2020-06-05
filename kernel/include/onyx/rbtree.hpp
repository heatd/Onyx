/*
* Copyright (c) 2020 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#ifndef _CARBON_RBTREE_HPP
#define _CARBON_HBTREE_HPP

#if 0
#include <utility>
#include <stdexcept>
#include <iostream>
#endif

#include <onyx/utility.hpp>
#include <onyx/pair.hpp>

#include <assert.h>

namespace cul
{

enum class rb_color
{
	red = 0,
	black 
};

template <typename Key, typename T>
class rb_node
{
public:
	rb_node *parent, *left {nullptr}, *right {nullptr};
	Key key;
	T data;
	rb_color color;

	rb_node(rb_node *parent, Key key, const T& d) : parent(parent), key(key),
						data(d), color(rb_color::red) {}
	rb_node(rb_node *parent, Key key, T&& d) : parent(parent), key(key),
						data(d), color(rb_color::red) {}
	rb_node(rb_node *parent, Key key) : parent(parent), key(key), data{},
						color(rb_color::red) {}
	~rb_node() = default;

	rb_color get_color()
	{
		return color;
	}

	void set_color(rb_color new_color)
	{
		color = new_color;
	}

	void recolor()
	{
		if(color == rb_color::red)
			color = rb_color::black;
		else
			color = rb_color::red;
	}

	bool is_root()
	{
		return parent == nullptr;
	}

	rb_node<Key, T> *get_grandparent()
	{
		if(!parent)
			return nullptr;
		return parent->parent;
	}

	rb_node<Key, T> *get_uncle()
	{
		auto grandparent = get_grandparent();
		if(!grandparent)
			return nullptr;

		rb_node<Key, T> *uncle;

		if(grandparent->left == parent)
			uncle = grandparent->right;
		else
			uncle = grandparent->left;
		
		return uncle;
	}

	bool triangle()
	{
		auto grandparent = get_grandparent();
		if(!grandparent)
			return false;

		return (parent->left == this && grandparent->right == parent) ||
		       (parent->right == this && grandparent->left == parent);
	}

	bool line()
	{
		auto grandparent = get_grandparent();
		if(!grandparent)
			return false;

		return (parent->left == this && grandparent->left == parent) ||
		       (parent->right == this && grandparent->right == parent);
	}

	void swap(rb_node<Key, T> *node)
	{
		auto tmp_key = cul::move(node->key);
		auto tmp_data = cul::move(node->data);

		node->key = cul::move(key);
		node->data = cul::move(data);

		key = cul::move(tmp_key);
		data = cul::move(tmp_data);
	}

	rb_node<Key, T> *max()
	{
		auto n = this;

		while(n->right) n = n->right;

		return n;
	}

	rb_node<Key, T> *min()
	{
		auto n = this;

		while(n->left) n = n->left;

		return n;
	}

	rb_node<Key, T> *prev()
	{
		if(left)
			return left->max();
		
		auto p = parent;
		auto node = this;

		while(p & p->left == node)
		{
			node = p;
			p = node->parent;
		}

		return parent;
	}

	rb_node<Key, T> *next()
	{
		if(right)
			return right->min();
		
		auto p = parent;
		auto node = this;

		while(p & p->right == node)
		{
			node = p;
			p = node->parent;
		}

		return parent;
	}
};

template <typename Key, typename T>
class rb_tree
{
private:
	rb_node<Key, T> *root;
	rb_node<Key, T>** __get_pointer_to_change(rb_node<Key, T> *node)
	{
		if(!node->parent)
			return &root;
		if(node->parent->left == node)
			return &node->parent->left;
		return &node->parent->right;
	}

	void rotate_left(rb_node<Key, T> *node)
	{
		auto pp = __get_pointer_to_change(node);

		*pp = node->right;
		
		auto right_node = node->right;

		right_node->parent = node->parent;
		node->parent = right_node;

		node->right = right_node->left;
		if(node->right)
			node->right->parent = node;
		right_node->left = node;
	}

	void rotate_right(rb_node<Key, T> *node)
	{
		auto pp = __get_pointer_to_change(node);

		*pp = node->left;
		
		auto left_node = node->left;

		left_node->parent = node->parent;
		node->parent = left_node;

		node->left = left_node->right;
		if(node->left)
			node->left->parent = node;
		left_node->right = node;
	}

	rb_color get_color_for_node(rb_node<Key, T> *n)
	{
		if(!n)
			return rb_color::black;
		return n->get_color();
	}

	void rebalance_node(rb_node<Key, T> *n)
	{
		//std::cout << "Rebalancing " << n->key << "\n";
		if(n->is_root() && n->get_color() == rb_color::red)
		{
			//std::cout << "case0\n";
			/* Case 0: n is root */
			/* Just recolor it black */
			n->set_color(rb_color::black);
		}
		else if(n->get_uncle() && n->get_uncle()->color == rb_color::red)
		{
			//std::cout << "case1\n";
			/* Case 1: n's uncle is red */
			/* Recolor the parent, uncle, and grandparent */
			auto uncle = n->get_uncle();
			n->parent->recolor();
			uncle->recolor();
			n->get_grandparent()->recolor();
		}
		else
		{
			auto uncle = n->get_uncle();

			if(get_color_for_node(uncle) == rb_color::black)
			{
				/* Case 2: n's uncle is black and n, n's parent and n's
					grandparent form a triangle */
				if(n->triangle())
				{
					//std::cout << "case2\n";
					/* In this case, rotate to the direction opposite to us(n) */
					if(n->parent->left == n)
						rotate_right(n->parent);
					else
						rotate_left(n->parent);
				}
				else if(n->line())
				{
					//std::cout << "case3\n";
					auto grandparent = n->get_grandparent();
					auto p = n->parent;
					/* Case 3: n's uncle is black and n, n's parent and
					 * gp form a line */
					/* Rotate the grandparent to the opposite direction of us */
					if(n->parent->left == n)
						rotate_right(grandparent);
					else
						rotate_left(grandparent);
					
					/* We'll also need to recolor the original
					 * parent and grandparent */
					grandparent->recolor();
					p->recolor();
				}
			}
		}

	}

	void rebalance(rb_node<Key, T> *n)
	{
		while(n->parent &&
			n->parent->get_color() == rb_color::red)
		{
			auto parent = n->parent;
			if(n->get_color() == rb_color::red)
				rebalance_node(n);
			n = parent;
		}

		root->set_color(rb_color::black);
	}

	rb_node<Key, T> *__find(const Key k) const
	{
		auto n = root;

		while(n != nullptr)
		{
			if(n->key < k)
				n = n->right;
			else if(n->key > k)
				n = n->left;
			else
				return n;
		}

		return nullptr;
	}

	static inline bool node_is_black(rb_node<Key, T> *node)
	{
		return !node || node->get_color() == rb_color::black;
	}

	void rb_delete_fixup(rb_node<Key, T> *node, rb_node<Key, T> *p, bool left)
	{
		while(node != root && node_is_black(node))
		{
			if(left)
			{
				auto w = p->right;
				if(w->get_color() == rb_color::red)
				{
					//std::cout << "case1 left\n";
					/* Case 1 -  Recolor w, w's parent and rotate the
					 parent to the left */
					w->set_color(rb_color::black);
					p->set_color(rb_color::red);
					rotate_left(p);
					w = p->right;
				}

				if(node_is_black(w->left) && node_is_black(w->right))
				{
					//std::cout << "case2 left\n";
					/* Case 2 - Both nodes are black - (Re)color w as red */
					w->set_color(rb_color::red);
					node = p;
					p = node->parent;
					left = p && p->left == node; 
				}
				else
				{
					if(node_is_black(w->right))
					{
						//std::cout << "case3 left\n";
						/* Case 3 - Recolor w and w.left */
						w->left->set_color(rb_color::black);
						w->set_color(rb_color::red);
						rotate_right(w);
						w = p->right;
					}

					//std::cout << "case4 left\n";

					/* Case 4 */

					w->set_color(p->get_color());

					if(w->right)	w->right->set_color(rb_color::black);
					p->set_color(rb_color::black);
					rotate_left(p);
					break;
				}
			}
			else
			{
				auto w = p->left;
				if(w->get_color() == rb_color::red)
				{
					//std::cout << "case1 right\n";
					/* Case 1 -  Recolor w, w's parent and rotate the
					 parent to the left */
					w->set_color(rb_color::black);
					p->set_color(rb_color::red);
					rotate_right(p);
					w = p->left;
				}

				if(node_is_black(w->left) && node_is_black(w->right))
				{
					//std::cout << "case2 right\n";
					/* Case 2 - Both nodes are black - (Re)color w as red */
					w->set_color(rb_color::red);
					node = p;
					p = node->parent;
					left = p && p->left == node; 
				}
				else
				{
					if(node_is_black(w->left))
					{
						//std::cout << "case3 right\n";
						/* Case 3 - Recolor w and w.right */
						w->right->set_color(rb_color::black);
						w->set_color(rb_color::red);
						rotate_left(w);
						w = p->left;
					}

					//std::cout << "case4 right\n";
					/* Case 4 */

					w->set_color(p->get_color());

					if(w->left)	w->left->set_color(rb_color::black);
					p->set_color(rb_color::black);
					rotate_right(p);
					break;
				}
			}
		}

		if(node)
			node->set_color(rb_color::black);
	}

	rb_node<Key, T> *min()
	{
		auto node = root;

		if(!node)
			return nullptr;
		
		return node->min();
	}

	rb_node<Key, T> *max()
	{
		auto node = root;

		if(!node)
			return nullptr;
		
		return node->max();
	}
public:

	rb_tree() : root(nullptr) {}

	bool insert(const cul::pair<const Key, T>& vals)
	{ 
		auto& key = vals.first;

		auto *pp = &root;
		rb_node<Key, T> *parent = nullptr;
	 
		while(*pp != nullptr)
		{
			parent = *pp;
			if(key < (*pp)->key)
			{
				pp = &(*pp)->left;
			}
			else if(key > (*pp)->key)
			{
				pp = &(*pp)->right;
			}
			else
			{
				return false;
			}
		}

		auto new_node = new rb_node<Key, T>{parent, key, vals.second};
		if(!new_node)
			return false;

		*pp = new_node;

		rebalance(new_node);

		return true;
	}

	bool remove(const Key k)
	{
		auto node = __find(k);
		if(!node)
			return false;

		auto y = node;
	
		if(node->left && node->right)
		{
			y = node->right;
			y = y->min();
			y->swap(node);
		}
		else
		{
			y = node;
		}

		auto x = y->left != nullptr ? y->left : y->right;

		if(x) x->parent = y->parent;

		bool left = y->parent != nullptr && y->parent->left == y;

		if(!y->parent)
			root =  x;
		else if(left)
			y->parent->left = x;
		else
			y->parent->right = x;
		
		if(y->get_color() == rb_color::black && root)
			rb_delete_fixup(x, y->parent, left);

		delete y;
	
		return true;
	}

	#include "rbtree_iterator.hpp"

	rb_tree_iterator begin() const
	{
		return rb_tree_iterator{this};
	}

	rb_tree_iterator end() const
	{
		return rb_tree_iterator{};
	}

	const rb_tree_iterator cbegin() const
	{
		return rb_tree_iterator{this};
	}

	const rb_tree_iterator cend() const
	{
		return rb_tree_iterator{};
	}

	rb_tree_iterator find(const Key k) const
	{
		auto node = __find(k);
		if(!node)
			return end();
		return rb_tree_iterator{node};
	}
};

}

#endif
