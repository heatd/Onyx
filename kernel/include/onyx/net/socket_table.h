/*
 * Copyright (c) 2020 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 */

#ifndef _ONYX_NET_SOCKET_TABLE_H
#define _ONYX_NET_SOCKET_TABLE_H

#include <onyx/net/inet_socket.h>
#include <onyx/net/netif.h>
#include <onyx/spinlock.h>

#include <onyx/hashtable.hpp>
#include <onyx/utility.hpp>

#ifndef CONFIG_SOCKET_HASHTABLE_SIZE
#define CONFIG_SOCKET_HASHTABLE_SIZE 512
#endif

class socket_table
{
private:
    cul::hashtable2<struct inet_socket *, CONFIG_SOCKET_HASHTABLE_SIZE, uint32_t,
                    &inet_socket::make_hash>
        socket_hashtable;
    struct spinlock lock_[CONFIG_SOCKET_HASHTABLE_SIZE];

public:
    constexpr socket_table() : socket_hashtable{}, lock_{}
    {
        for (auto &l : lock_)
            spinlock_init(&l);
    }

    ~socket_table() = default;

    CLASS_DISALLOW_MOVE(socket_table);
    CLASS_DISALLOW_COPY(socket_table);

    size_t index_from_hash(fnv_hash_t hash)
    {
        return socket_hashtable.get_hashtable_index(hash);
    }

    void lock(fnv_hash_t hash)
    {
        spin_lock(&lock_[index_from_hash(hash)]);
    }

    void unlock(fnv_hash_t hash)
    {
        spin_unlock(&lock_[index_from_hash(hash)]);
    }

    inet_socket *get_socket(const socket_id &id, unsigned int flags, unsigned int inst = 0);
    bool add_socket(inet_socket *sock, unsigned int flags);
    bool remove_socket(inet_socket *sock, unsigned int flags);
};

#endif
