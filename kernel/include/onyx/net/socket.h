/*
 * Copyright (c) 2018 - 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef _ONYX_NET_SOCKET_H
#define _ONYX_NET_SOCKET_H

#include <stddef.h>
#include <stdint.h>

#include <onyx/fnv.h>
#include <onyx/hybrid_lock.h>
#include <onyx/iovec_iter.h>
#include <onyx/net/netif.h>
#include <onyx/net/proto_family.h>
#include <onyx/object.h>
#include <onyx/refcount.h>
#include <onyx/semaphore.h>
#include <onyx/vector.h>
#include <onyx/vfs.h>
#include <onyx/wait_queue.h>

#include <onyx/expected.hpp>
#include <onyx/hashtable.hpp>
#include <onyx/pair.hpp>

#define PROTOCOL_IPV4 1
#define PROTOCOL_IPV6 2
#define PROTOCOL_UDP  3
#define PROTOCOL_TCP  4
#define PROTOCOL_UNIX 5

#define DEFAULT_RX_MAX_BUF UINT16_MAX
#define DEFAULT_TX_MAX_BUF UINT16_MAX

struct socket_conn_request
{
    struct sockaddr saddr;
    struct list_head list_node;
};

struct socket;

struct recv_packet
{
    union {
        sockaddr_in in4;
        sockaddr_in6 in6;
    } src_addr;

    socklen_t addr_len;
    void *payload;
    size_t size;
    size_t read;
    list_head_cpp<recv_packet> list_node;
    cul::vector<uint8_t> ancilliary_data;

public:
    recv_packet()
        : src_addr{}, addr_len{}, payload{}, size{}, read{}, list_node{this}, ancilliary_data{}
    {
    }

    ~recv_packet()
    {
        free(payload);
    }
};

class recv_queue
{
private:
    wait_queue recv_wait;
    struct spinlock recv_queue_lock;
    struct list_head recv_list;
    size_t total_data_in_buffers;
    socket *sock;

    struct list_head *get_recv_packet_list(int msg_flags, size_t required_data, int &error);
    bool has_data_available(int msg_flags, size_t required_data);
    void clear_packets();

public:
    recv_queue(socket *sock) : recv_queue_lock{}, total_data_in_buffers{0}, sock{sock}
    {
        init_wait_queue_head(&recv_wait);
        INIT_LIST_HEAD(&recv_list);
    }

    ~recv_queue();

    ssize_t recvfrom(void *buf, size_t len, int flags, sockaddr *src_addr, socklen_t *slen);
    void add_packet(recv_packet *p);
    bool poll(void *poll_file);
};

struct socket : public refcountable
{
private:
public:
    int type;
    int proto;
    int domain;
    recv_queue in_band_queue;
    recv_queue oob_data_queue;
    unsigned int flags;
    unsigned int sock_err;

    /* This lock serialises binds, connects, listens, sends, recvs, whatever, on the socket,
     * to prevent race conditions.
     */

    hybrid_lock socket_lock;
    bool bound;
    bool connected;

    struct semaphore listener_sem;
    struct spinlock conn_req_list_lock;
    struct list_head conn_request_list;
    int nr_pending;
    int backlog;

    proto_family *proto_domain;

    struct list_head socket_backlog;

    unsigned int rx_max_buf;
    unsigned int tx_max_buf;

    bool reuse_addr : 1;

    bool broadcast_allowed : 1;
    bool proto_needs_work : 1 {0};

    hrtime_t rcv_timeout;
    hrtime_t snd_timeout;
    unsigned int shutdown_state;

    /* Define a default constructor here */
    socket()
        : type{}, proto{}, domain{}, in_band_queue{this}, oob_data_queue{this}, flags{}, sock_err{},
          socket_lock{}, bound{}, connected{}, listener_sem{}, conn_req_list_lock{},
          conn_request_list{}, nr_pending{}, backlog{}, proto_domain{},
          rx_max_buf{DEFAULT_RX_MAX_BUF}, tx_max_buf{DEFAULT_TX_MAX_BUF}, reuse_addr{false},
          rcv_timeout{0}, snd_timeout{0}, shutdown_state{}
    {
        INIT_LIST_HEAD(&socket_backlog);
    }

    virtual ~socket()
    {
    }

    ssize_t default_recvfrom(void *buf, size_t len, int flags, sockaddr *src_addr, socklen_t *slen);
    bool has_data_available(int msg_flags, size_t required_data);
    virtual short poll(void *poll_file, short events);

    template <typename Type>
    expected<Type, int> get_socket_option(const void *optval, const socklen_t optlen)
    {
        if (optlen != sizeof(Type))
            return unexpected<int>{-EINVAL};

        Type t;
        memcpy(&t, optval, optlen);

        return cul::move(t);
    }

    int getsockopt_socket_level(int optname, void *optval, socklen_t *optlen);
    int setsockopt_socket_level(int optname, const void *optval, socklen_t optlen);

    template <typename Type>
    static int put_option(const Type &val, void *option, socklen_t *length)
    {
        unsigned int length_ = min(sizeof(Type), (size_t) *length);
        memcpy(option, &val, length_);
        *length = length_;

        return 0;
    }

    bool listening() const
    {
        return backlog != 0;
    }

    static bool int_to_truthy(int i)
    {
        return i != 0;
    }

    static int truthy_to_int(bool val)
    {
        return (int) val;
    }

    bool has_sock_err() const
    {
        return sock_err != 0;
    }

    int consume_sock_err()
    {
        int ret = -sock_err;
        sock_err = 0;
        return ret;
    }

#define CONSUME_SOCK_ERR \
    if (has_sock_err())  \
    return consume_sock_err()

    virtual int listen();
    virtual socket *accept(int flags);
    virtual int bind(sockaddr *addr, socklen_t addrlen);
    virtual int connect(sockaddr *addr, socklen_t addrlen, int flags);
    virtual ssize_t sendmsg(const struct msghdr *msg, int flags);
    virtual ssize_t recvmsg(struct msghdr *msg, int flags);
    virtual int getsockname(sockaddr *addr, socklen_t *addrlen);
    virtual int getpeername(sockaddr *addr, socklen_t *addrlen);
    virtual int shutdown(int how);
    virtual int getsockopt(int level, int optname, void *optval, socklen_t *optlen) = 0;
    virtual int setsockopt(int level, int optname, const void *optval, socklen_t optlen) = 0;

    virtual void close()
    {
        unref();
    }

    virtual void handle_backlog()
    {
    }

    void add_backlog(list_head *node)
    {
        list_add_tail(node, &socket_backlog);
    }
};

template <typename T>
sockaddr &sa_generic(T &s)
{
    return (sockaddr &) s;
}

#define SOL_ICMP   800
#define SOL_TCP    6
#define SOL_UDP    21
#define SOL_ICMPV6 58

void socket_init(struct socket *socket);

// Internal representations of the shutdown state of the socket
#define SHUTDOWN_RD   (1 << 0)
#define SHUTDOWN_WR   (1 << 1)
#define SHUTDOWN_RDWR (SHUTDOWN_RD | SHUTDOWN_WR)

#endif
