/*
 * Copyright (c) 2020 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 */

#ifndef _ONYX_NET_INET_PROTO_H
#define _ONYX_NET_INET_PROTO_H

#include <onyx/utility.hpp>

class socket_table;

class inet_proto
{
private:
    const char *name;
    socket_table *sock_tab;

public:
    CLASS_DISALLOW_COPY(inet_proto);
    CLASS_DISALLOW_MOVE(inet_proto);

    inet_proto(const char *name, socket_table *sock_tab = nullptr) : name{name}, sock_tab{sock_tab}
    {
    }

    const char *get_name() const
    {
        return name;
    }

    socket_table *get_socket_table() const
    {
        return sock_tab;
    }
};

#endif
