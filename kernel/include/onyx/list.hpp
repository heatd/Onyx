/*
* Copyright (c) 2019 Pedro Falcato
* This file is part of Carbon, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#ifndef _CARBON_LIST_H
#define _CARBON_LIST_H

#include <onyx/utility.hpp>

template <typename T>
class linked_list;

template <typename T>
class linked_list_iterator;

template <typename T>
class linked_list_node
{
public:
	T data;
	linked_list_node<T> *prev, *next;
	friend class linked_list<T>;
	friend class linked_list_iterator<T>;

	linked_list_node(const T& data) : data(data), prev(nullptr), next(nullptr)
	{
	}

	linked_list_node(T&& data) : data(cul::move(data)), prev(nullptr), next(nullptr)
	{
	}

	inline void append(linked_list_node<T> *node)
	{
		next = node;
		node->prev = this;
	}

	linked_list_node<T>* operator++(int)
	{
		return next;
	}
};

template <typename T>
class linked_list_iterator
{
private:
	linked_list_node<T> *current_node;
	friend class linked_list<T>;
public:
	linked_list_iterator() : current_node(nullptr)
	{}

	linked_list_iterator(linked_list_node<T> *node)
	{
		current_node = node;
	}

	linked_list_iterator<T>& operator++()
	{
		current_node = current_node->next;
		return *this;
	}

	linked_list_iterator<T> operator++(int)
	{
		linked_list_iterator<T> copy(*this);
		++(*this);
		return copy;
	}

	T& operator*()
	{
		return current_node->data;
	}

	const T& operator*() const
	{
		return current_node->data;
	}

	bool operator==(const linked_list_iterator<T>& a) const
	{
		return current_node == a.current_node;
	}

	bool operator!=(const linked_list_iterator<T>& a) const
	{
		return current_node != a.current_node;
	}
};

template <typename T>
class linked_list
{
private:
	linked_list_node<T> *head, *tail;
public:
	linked_list() : head(nullptr), tail(nullptr){}

	/* Low-level-ish interface to the linked list */
	linked_list_node<T> *get_head() const
	{
		return head;
	}

	linked_list_node<T> *get_tail() const
	{
		return tail;
	}

	bool add(const T& data)
	{
		auto p = new linked_list_node<T>(data);
		if(!p)
			return false;
		
		if(head)
		{
			tail->append(p);
		}
		else
		{
			head = p;
		}

		tail = p;

		return true;
	}

	bool add(T&& data)
	{
		auto p = new linked_list_node<T>(cul::move(data));
		if(!p)
			return false;
		
		if(head)
		{
			tail->append(p);
		}
		else
		{
			head = p;
		}

		tail = p;

		return true;
	}

	linked_list_iterator<T> begin()
	{
		linked_list_iterator<T> it(head);
		return it;
	}

	linked_list_iterator<T> end()
	{
		return linked_list_iterator<T>(nullptr);
	}

	inline bool remove(const T& data, linked_list_iterator<T>& it)
	{
		while(it != end())
		{
			linked_list_node<T> *node = it.current_node;

			if(node->data == data)
			{
				if(node->prev)
					node->prev->next = node->next;
				else
					head = node->next;

				if(node->next)
					node->next->prev = node->prev;
				else
					tail = node->prev;
				
				delete node;

				return true;
			}

			++it;
		}

		return false;
	}

	inline bool remove(const T& data)
	{
		linked_list_iterator<T> it = begin();

		return remove(data, it);
	}

	inline bool is_empty()
	{
		return (head == nullptr);
	}

	bool Copy(linked_list<T> *list)
	{
		for(auto it = list->begin(); it != list->end(); it++)
		{
			if(!this->add(*it))
			{
				/* Undo */
				for(auto n = list->begin(); n != it; n++)
					this->remove(*n);
				
				return false;
			}
		}

		return true;
	}
};

#endif
