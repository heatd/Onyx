/*
* Copyright (c) 2019 Pedro Falcato
* This file is part of Carbon, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#ifndef _CARBON_LIST_H
#define _CARBON_LIST_H

template <typename T>
class LinkedList;

template <typename T>
class LinkedListIterator;

template <typename T>
class LinkedListNode
{
public:
	T data;
	LinkedListNode<T> *prev, *next;
	friend class LinkedList<T>;
	friend class LinkedListIterator<T>;

	LinkedListNode(T data) : data(data), prev(nullptr), next(nullptr)
	{
	}

	inline void Append(LinkedListNode<T> *node)
	{
		next = node;
		node->prev = this;
	}

	LinkedListNode<T>* operator++(int)
	{
		return next;
	}
};

template <typename T>
class LinkedListIterator
{
private:
	LinkedListNode<T> *current_node;
	friend class LinkedList<T>;
public:
	LinkedListIterator() : current_node(nullptr)
	{}

	LinkedListIterator(LinkedListNode<T> *node)
	{
		current_node = node;
	}

	LinkedListIterator<T>& operator++()
	{
		current_node = current_node->next;
		return *this;
	}

	LinkedListIterator<T> operator++(int)
	{
		LinkedListIterator<T> copy(*this);
		++(*this);
		return copy;
	}

	T& operator*()
	{
		return current_node->data;
	}

	bool operator==(const LinkedListIterator<T>& a)
	{
		return current_node == a.current_node;
	}

	bool operator!=(const LinkedListIterator<T>& a)
	{
		return current_node != a.current_node;
	}
};

template <typename T>
class LinkedList
{
private:
	LinkedListNode<T> *head, *tail;
public:
	LinkedList<T>() : head(nullptr), tail(nullptr){}

	/* Low-level-ish interface to the linked list */
	LinkedListNode<T> *GetHead() const
	{
		return head;
	}

	LinkedListNode<T> *GetTail() const
	{
		return tail;
	}

	bool Add(T data)
	{
		auto p = new LinkedListNode<T>(data);
		if(!p)
			return false;
		
		if(head)
		{
			tail->Append(p);
		}
		else
		{
			head = p;
		}

		tail = p;

		return true;
	}

	LinkedListIterator<T> begin()
	{
		LinkedListIterator<T> it(head);
		return it;
	}

	LinkedListIterator<T> end()
	{
		return LinkedListIterator<T>(nullptr);
	}

	inline bool Remove(const T& data, LinkedListIterator<T>& it)
	{
		while(it != end())
		{
			LinkedListNode<T> *node = it.current_node;

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

	inline bool Remove(const T& data)
	{
		LinkedListIterator<T> it = begin();

		return Remove(data, it);
	}

	inline bool IsEmpty()
	{
		return (head == nullptr);
	}

	bool Copy(LinkedList<T> *list)
	{
		for(auto it = list->begin(); it != list->end(); it++)
		{
			if(!this->Add(*it))
			{
				/* Undo */
				for(auto n = list->begin(); n != it; n++)
					this->Remove(*n);
				
				return false;
			}
		}

		return true;
	}
};

#endif