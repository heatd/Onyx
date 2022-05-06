/*
 * Copyright (c) 2020 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 */
#include <onyx/net/inet_socket.h>
#include <onyx/net/socket_table.h>

inet_socket *socket_table::get_socket(const socket_id &id, unsigned int flags, unsigned int inst)
{
    auto hash = inet_socket::make_hash_from_id(id);
    bool unlocked = flags & GET_SOCKET_UNLOCKED;
    auto index = socket_hashtable.get_hashtable_index(hash);

    if (!unlocked)
        lock(hash);

    /* Alright, so this is the standard hashtable thing - hash the socket_id,
     * get the iterators, and then iterate through the list and compare the
     * socket_id with the socket's internal id. This should be pretty efficient.
     * My biggest worry right now is that the hashtables may be too small for a lot of system load.
     * We should do something like linux where its hash tables are allocated dynamically,
     * based on the system memory's size.
     */

    auto list = socket_hashtable.get_hashtable(index);

    inet_socket *ret = nullptr;

    list_for_every (list)
    {
        auto sock = list_head_cpp<inet_socket>::self_from_list_head(l);

        if (sock->is_id(id, flags) && inst-- == 0)
        {
            ret = sock;
            break;
        }
    }

    /* GET_SOCKET_CHECK_EXISTENCE is very useful for operations like bind,
     * as to avoid two extra atomic operations.
     */

    if (ret && !(flags & GET_SOCKET_CHECK_EXISTENCE))
        ret->ref();

    if (!unlocked)
        unlock(hash);

    return ret;
}

bool socket_table::add_socket(inet_socket *sock, unsigned int flags)
{
    bool unlocked = flags & ADD_SOCKET_UNLOCKED;

    const socket_id id(sock->proto, sock->domain, sock->src_addr, sock->dest_addr);
    auto hash = inet_socket::make_hash_from_id(id);

#if 0
    printk("Binding source %u dest %u\n", sock->src_addr.port, sock->dest_addr.port);
#endif
    if (!unlocked)
        lock(hash);

    socket_hashtable.add_element(sock, sock->bind_table_node.to_list_head());

    if (!unlocked)
        unlock(hash);

    return true;
}

bool socket_table::remove_socket(inet_socket *sock, unsigned int flags)
{
    bool unlocked = flags & REMOVE_SOCKET_UNLOCKED;

    const socket_id id(sock->proto, sock->domain, sock->src_addr, sock->dest_addr);
    auto hash = inet_socket::make_hash(sock);

    if (!unlocked)
        lock(hash);

    socket_hashtable.remove_element(sock, sock->bind_table_node.to_list_head());

    if (!unlocked)
        unlock(hash);

    return true;
}
