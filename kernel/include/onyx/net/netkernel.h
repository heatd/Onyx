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
public:
    shared_ptr<netkernel_object> dst;

    netkernel_socket(int type) : socket{}, dst{}
    {
        domain = AF_NETKERNEL;
        proto = NETKERNEL_PROTO;
        this->type = type;
    }

    int getsockopt(int level, int optname, void *optval, socklen_t *optlen) override;
    int setsockopt(int level, int optname, const void *optval, socklen_t optlen) override;
    int connect(sockaddr *addr, socklen_t addrlen, int flags) override;
    ssize_t sendmsg(const struct msghdr *msg, int flags) override;
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
