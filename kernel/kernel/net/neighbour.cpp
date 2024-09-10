/*
 * Copyright (c) 2020 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 */
#include <onyx/net/neighbour.h>
#include <onyx/panic.h>
#include <onyx/scoped_lock.h>

#include <onyx/hashtable.hpp>
#include <onyx/memory.hpp>

void neighbour_revalidate(clockevent* ev)
{
    // TODO: Implement
    ev->deadline = clocksource_get_time() + NS_PER_SEC * 60 * 20;
}

cul::pair<shared_ptr<neighbour>, bool> neighbour_table::add(const neigh_proto_addr& addr,
                                                            bool only_lookup)
{
    scoped_lock g{lock};

    auto hash = hash_protoaddr(addr, domain);

    auto it = neighbour_cache.get_hash_list_begin(hash);
    auto end = neighbour_cache.get_hash_list_end(hash);

    while (it != end)
    {
        auto neigh = *it;
        auto n_hwaddr = neigh->hwaddr();
        if (neigh->addr_equals(addr))
            return {neigh, false};
        it++;
    }

    if (only_lookup)
        return {nullptr, false};

    auto ptr = make_shared<neighbour>(domain, addr);

    if (!ptr)
        return {nullptr, false};

    ptr->flags |= NEIGHBOUR_FLAG_UNINITIALISED;

    if (!neighbour_cache.add_element(ptr))
        return {nullptr, false};

    return {ptr, true};
}

void neighbour_table::remove(neighbour* ptr)
{
    scoped_lock g{lock};
    auto& hw = ptr->proto_addr;
    auto hash = hash_protoaddr(hw, domain);

    auto it = neighbour_cache.get_hash_list_begin(hash);
    auto end = neighbour_cache.get_hash_list_end(hash);

    while (it != end)
    {
        auto neigh = *it;
        if (neigh == ptr)
        {
            neighbour_cache.remove_element(neigh, hash, it);
            return;
        }

        it++;
    }
}

void neighbour_table::clear_cache()
{
    scoped_lock g{lock};

    neighbour_cache.empty();
}

fnv_hash_t hash_neighbour(shared_ptr<neighbour>& neigh)
{
    return hash_protoaddr(neigh->proto_addr, neigh->get_domain());
}
