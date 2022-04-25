/*
 * Copyright (c) 2020 - 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef _ONYX_NET_NETKERNEL_H
#define _ONYX_NET_NETKERNEL_H

#include <onyx/net/socket.h>
#include <onyx/public/netkernel.h>
#include <onyx/rwlock.h>
#include <onyx/vector.h>

#include <onyx/expected.hpp>
#include <onyx/memory.hpp>
#include <onyx/string_view.hpp>

namespace netkernel
{

class netkernel_object;

class netkernel_socket : public socket
{
private:
    spinlock rx_packet_list_lock;
    struct list_head rx_packet_list;
    wait_queue rx_wq;

    packetbuf *get_rx_head()
    {
        if (list_is_empty(&rx_packet_list))
            return nullptr;

        return list_head_cpp<packetbuf>::self_from_list_head(list_first_element(&rx_packet_list));
    }

    bool has_data_available()
    {
        return !list_is_empty(&rx_packet_list);
    }

    int wait_for_dgrams()
    {
        return wait_for_event_locked_interruptible(&rx_wq, !list_is_empty(&rx_packet_list),
                                                   &rx_packet_list_lock);
    }

    void rx_pbuf(packetbuf *buf)
    {
        scoped_lock g{rx_packet_list_lock};

        buf->ref();

        list_add_tail(&buf->list_node, &rx_packet_list);

        wait_queue_wake_all(&rx_wq);
    }

public:
    shared_ptr<netkernel_object> dst;

    netkernel_socket(int type) : socket{}, rx_packet_list_lock{}, rx_packet_list{}, rx_wq{}, dst{}
    {
        domain = AF_NETKERNEL;
        proto = NETKERNEL_PROTO;
        INIT_LIST_HEAD(&rx_packet_list);
        spinlock_init(&rx_packet_list_lock);
        init_wait_queue_head(&rx_wq);
        this->type = type;
    }

    int getsockopt(int level, int optname, void *optval, socklen_t *optlen) override;
    int setsockopt(int level, int optname, const void *optval, socklen_t optlen) override;
    int connect(sockaddr *addr, socklen_t addrlen, int flags) override;
    ssize_t sendmsg(const struct msghdr *msg, int flags) override;
    ssize_t recvmsg(struct msghdr *msg, int flags) override;

    expected<packetbuf *, int> get_datagram(int flags)
    {
        scoped_lock g{rx_packet_list_lock};

        int st = 0;
        packetbuf *buf = nullptr;

        do
        {
            if (st == -EINTR)
                return unexpected<int>{st};

            buf = get_rx_head();
            if (!buf && flags & MSG_DONTWAIT)
                return unexpected<int>{-EWOULDBLOCK};

            st = wait_for_dgrams();
        } while (!buf);

        g.keep_locked();

        return buf;
    }
};

/**
 * @brief Describes an object in the netkernel namespace
 *
 */
class netkernel_object
{
protected:
    netkernel_object *parent;
    const char *name;
    unsigned int flags;
    mutable rwlock children_lock;
    cul::vector<shared_ptr<netkernel_object>> children;

public:
    void set_parent(netkernel_object *p)
    {
        parent = p;
    }

    bool add_child(shared_ptr<netkernel_object> &c)
    {
        scoped_rwlock<rw_lock::write> g{children_lock};

        auto st = children.push_back(c);

        if (st)
            c->set_parent(this);

        return st;
    }

    shared_ptr<netkernel_object> find(const std::string_view &name)
    {
        scoped_rwlock<rw_lock::read> g{children_lock};

        for (auto &o : children)
        {
            if (!name.compare(o->name))
                return o;
        }

        return nullptr;
    }

    netkernel_object(const char *name) : parent{}, name{name}, flags{}, children_lock{}, children{}
    {
        rwlock_init(&children_lock);
    }

    unsigned int get_flags() const
    {
        return flags;
    }

    void set_flags(unsigned int new_f)
    {
        flags = new_f;
    }

    virtual ~netkernel_object()
    {
    }

    virtual expected<netkernel_hdr *, int> serve_request(netkernel_hdr *msg)
    {
        return unexpected<int>{-ENXIO};
    }
};

#define NETKERNEL_OBJECT_DEAD         (1 << 0)
#define NETKERNEL_OBJECT_PATH_ELEMENT (1 << 1)

shared_ptr<netkernel_object> open(std::string_view path);

socket *create_socket(int type);

} // namespace netkernel

#endif
