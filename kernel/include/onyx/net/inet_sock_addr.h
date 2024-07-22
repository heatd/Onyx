/*
 * Copyright (c) 2020 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 */

#ifndef _ONYX_NET_INET_SOCK_ADDR_H
#define _ONYX_NET_INET_SOCK_ADDR_H

#include <uapi/netinet.h>
#include <uapi/socket.h>

constexpr bool operator==(const in_addr& lhs, const in_addr& rhs)
{
    return lhs.s_addr == rhs.s_addr;
}

constexpr bool operator==(const in6_addr& lhs, const in6_addr& rhs)
{
    return rhs.s6_addr32[0] == lhs.s6_addr32[0] && rhs.s6_addr32[1] == lhs.s6_addr32[1] &&
           rhs.s6_addr32[2] == lhs.s6_addr32[2] && rhs.s6_addr32[3] == lhs.s6_addr32[3];
}

constexpr in6_addr operator&(const in6_addr& lhs, const in6_addr& rhs)
{
    in6_addr ret;
    ret.s6_addr32[0] = lhs.s6_addr32[0] & rhs.s6_addr32[0];
    ret.s6_addr32[1] = lhs.s6_addr32[1] & rhs.s6_addr32[1];
    ret.s6_addr32[2] = lhs.s6_addr32[2] & rhs.s6_addr32[2];
    ret.s6_addr32[3] = lhs.s6_addr32[3] & rhs.s6_addr32[3];

    return ret;
}

constexpr bool operator!=(const in6_addr& lhs, const in6_addr& rhs)
{
    return !(lhs == rhs);
}

struct inet_sock_address
{
    /* We keep two addresses here because I'd rather waste 4 bytes per inet socket than
     * have "shameful" undefined behavior on compilers that != G++(and possibly clang).
     * TL;DR we avoid the union here because union type punning is outlawed in C++ and we
     * might trigger that.
     */
    in_addr in4;
    in6_addr in6;
    in_port_t port;
    uint32_t v6_scope_id{0};

    constexpr inet_sock_address() : in4{}, in6{}, port{}
    {
    }

    explicit constexpr inet_sock_address(const sockaddr_in& sa)
        : in4{sa.sin_addr}, in6{}, port{sa.sin_port}
    {
    }

    explicit constexpr inet_sock_address(const sockaddr_in6& sa)
        : in4{}, in6{sa.sin6_addr}, port{sa.sin6_port}, v6_scope_id{sa.sin6_scope_id}
    {
    }

    explicit constexpr inet_sock_address(const in_addr& in4, in_port_t port)
        : in4{in4}, in6{}, port{port}
    {
    }

    explicit constexpr inet_sock_address(const in6_addr& in6, in_port_t port, uint32_t scope)
        : in4{}, in6{in6}, port{port}, v6_scope_id{scope}
    {
    }

    constexpr bool equals(const inet_sock_address& rhs, bool ipv4_mode) const
    {
        if (port != rhs.port)
            return false;

        if (ipv4_mode)
        {
            return in4 == rhs.in4;
        }
        else
        {
            bool scope_id_matters =
                IN6_IS_ADDR_MC_LINKLOCAL(in6.s6_addr) || IN6_IS_ADDR_LINKLOCAL(in6.s6_addr);
            return (!scope_id_matters || v6_scope_id == rhs.v6_scope_id) && in6 == rhs.in6;
        }
    }

    constexpr bool is_any(bool ipv4_mode) const
    {
        if (ipv4_mode)
            return in4 == in_addr{INADDR_ANY};
        else
            return in6 == in6addr_any;
    }
};

template <typename AddressType>
struct inet_domain_type
{
    static constexpr int domain = AF_UNSPEC;
};

template <>
struct inet_domain_type<in_addr>
{
    static constexpr int domain = AF_INET;
};

template <>
struct inet_domain_type<in6_addr>
{
    static constexpr int domain = AF_INET6;
};

template <typename AddressType>
inline constexpr int inet_domain_type_v = inet_domain_type<AddressType>::domain;

#endif
