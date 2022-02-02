/*
 * Copyright (c) 2019 Pedro Falcato
 * This file is part of Carbon, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 */

#ifndef _CARBON_HASHTABLE_H
#define _CARBON_HASHTABLE_H

#include <onyx/list.h>

#include <onyx/list.hpp>
#include <onyx/utility.hpp>

namespace cul
{

template <typename T, size_t number_entries, typename hash_type, hash_type (*hash_func)(T& data)>
class hashtable
{
private:
    linked_list<T> buckets[number_entries];

public:
    hashtable() : buckets()
    {
    }

    void empty_bucket(size_t i)
    {
        auto& bucket = buckets[i];

        for (auto it = bucket.begin(); it != bucket.end();)
        {
            auto& elem = *it;
            auto to_delete = it++;
            bucket.remove(elem, to_delete);
        }
    }

    void empty()
    {
        for (size_t i = 0; i < number_entries; i++)
        {
            if (buckets[i].is_empty())
                continue;
            empty_bucket(i);
        }
    }

    ~hashtable()
    {
        empty();
    }

    bool add_element(const T& elem)
    {
        auto hash = hash_func(const_cast<T&>(elem));

        auto index = hash % number_entries;
        return buckets[index].add(elem);
    }

    bool add_element(T&& elem)
    {
        auto hash = hash_func(elem);

        auto index = hash % number_entries;
        return buckets[index].add(cul::move(elem));
    }

    linked_list_iterator<T> get_hash_list_begin(hash_type hash)
    {
        auto index = hash % number_entries;
        return buckets[index].begin();
    }

    linked_list_iterator<T> get_hash_list_end(hash_type hash)
    {
        auto index = hash % number_entries;
        return buckets[index].end();
    }

    size_t get_hashtable_index(hash_type hash)
    {
        return hash % number_entries;
    }

    linked_list<T>& get_hashtable(size_t index)
    {
        return buckets[index];
    }

    bool remove_element(T& elem, hash_type hash, linked_list_iterator<T> it)
    {
        auto index = hash % number_entries;

        return buckets[index].remove(elem, it);
    }

    bool remove_element(T& elem)
    {
        auto hash = hash_func(elem);
        auto index = hash % number_entries;

        return remove_element(elem, hash, buckets[index].begin());
    }
};

/* This hashtable works for types with list_node(uses list_head)
 * It was made for futexes, but it's adaptable enough for everything else
 * that may want to use list_head.
 */
template <typename T, size_t number_entries, typename hash_type, hash_type (*hash_func)(T& data)>
class hashtable2
{
private:
    struct list_head buckets[number_entries];

public:
    constexpr hashtable2() : buckets()
    {
        for (auto& l : buckets)
            INIT_LIST_HEAD(&l);
    }

    ~hashtable2()
    {
    }

    void add_element(const T& elem, list_head* node)
    {
        auto hash = hash_func(const_cast<T&>(elem));

        auto index = hash % number_entries;
        list_add_tail(node, &buckets[index]);
    }

    void add_element(T& elem)
    {
        add_element(elem, &elem.list_node);
    }

    size_t get_hashtable_index(hash_type hash) const
    {
        return hash % number_entries;
    }

    list_head* get_hashtable(size_t index)
    {
        return &buckets[index];
    }

    void remove_element(T& elem, list_head* node)
    {
        list_remove(node);
    }

    void remove_element(T& elem)
    {
        remove_element(elem, &elem.list_node);
    }
};

}; // namespace cul

#endif
