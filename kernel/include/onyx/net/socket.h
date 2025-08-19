/*
 * Copyright (c) 2018 - 2025 Pedro Falcato
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
#include <onyx/object.h>
#include <onyx/packetbuf.h>
#include <onyx/page_frag.h>
#include <onyx/ref.h>

#ifdef __cplusplus
#include <onyx/refcount.h>
#include <onyx/vector.h>

#include <onyx/expected.hpp>
#endif

#include <onyx/vfs.h>
#include <onyx/wait_queue.h>

#define PROTOCOL_IPV4 1
#define PROTOCOL_IPV6 2
#define PROTOCOL_UDP  3
#define PROTOCOL_TCP  4
#define PROTOCOL_UNIX 5

#define DEFAULT_RX_MAX_BUF UINT16_MAX
#define DEFAULT_TX_MAX_BUF UINT16_MAX

struct socket;

struct kernel_msghdr
{
    void *msg_name;
    socklen_t msg_namelen;
    struct iovec_iter *msg_iter;
    void *msg_control;
    socklen_t msg_controllen;
    int msg_flags;
};

struct socket_ops
{
    void (*destroy)(struct socket *);
    int (*listen)(struct socket *);
    struct socket *(*accept)(struct socket *, int flags);
    int (*bind)(struct socket *, struct sockaddr *addr, socklen_t addrlen);
    int (*connect)(struct socket *, struct sockaddr *addr, socklen_t addrlen, int flags);
    ssize_t (*sendmsg)(struct socket *, const struct kernel_msghdr *msg, int flags);
    ssize_t (*recvmsg)(struct socket *, struct kernel_msghdr *msg, int flags);
    int (*getsockname)(struct socket *, struct sockaddr *addr, socklen_t *addrlen);
    int (*getpeername)(struct socket *, struct sockaddr *addr, socklen_t *addrlen);
    int (*shutdown)(struct socket *, int how);
    int (*getsockopt)(struct socket *, int level, int optname, void *optval, socklen_t *optlen);
    int (*setsockopt)(struct socket *, int level, int optname, const void *optval,
                      socklen_t optlen);
    void (*close)(struct socket *);
    void (*handle_backlog)(struct socket *);
    short (*poll)(struct socket *, void *poll_file, short events);
    void (*write_space)(struct socket *);
};

struct socket
{
    refcount_t refs;
    int type;
    int proto;
    int domain;
    unsigned int flags;
    unsigned int sock_err;

    /* This lock serialises binds, connects, listens, sends, recvs, whatever, on the socket,
     * to prevent race conditions.
     */

    struct hybrid_lock socket_lock;
    bool bound;
    bool connected;
    bool reuse_addr : 1;
    bool broadcast_allowed : 1;
    bool proto_needs_work : 1;
    bool dead : 1;
    bool sndbuf_locked : 1;
    bool rcvbuf_locked : 1;

    struct list_head socket_backlog;

    unsigned int sk_rcvbuf;
    unsigned int sk_sndbuf;
    unsigned sk_send_queued;
    unsigned sk_rmem;
    int backlog;
    unsigned int shutdown_state;

    hrtime_t rcv_timeout;
    hrtime_t snd_timeout;

    const struct socket_ops *sock_ops;

    /* Socket page frag info - used for allocating wmem */
    struct page_frag_info sock_pfi;

#ifdef __cplusplus
    /* Define a default constructor here */
    socket() : socket_lock{}
    {
        refs = REFCOUNT_INIT(1);
        proto_needs_work = 0;
        dead = 0;
        sndbuf_locked = 0;
        rcvbuf_locked = 0;
        type = 0;
        proto = 0;
        domain = 0;
        flags = 0;
        sock_err = 0;
        bound = false;
        connected = false;
        reuse_addr = false;
        sk_rcvbuf = DEFAULT_RX_MAX_BUF;
        sk_sndbuf = DEFAULT_TX_MAX_BUF;
        shutdown_state = 0;
        rcv_timeout = snd_timeout = 0;
        sock_ops = NULL;
        hybrid_lock_init(&socket_lock);
        INIT_LIST_HEAD(&socket_backlog);
        pfi_init(&sock_pfi);
        sk_send_queued = 0;
        sk_rmem = 0;
        backlog = 0;
    }

    ~socket()
    {
        pfi_destroy(&sock_pfi);
        sock_ops->destroy(this);
    }

    short poll(void *poll_file, short events);

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

    int listen();
    socket *accept(int flags);
    int bind(sockaddr *addr, socklen_t addrlen);
    int connect(sockaddr *addr, socklen_t addrlen, int flags);
    ssize_t sendmsg(const struct kernel_msghdr *msg, int flags);
    ssize_t recvmsg(struct kernel_msghdr *msg, int flags);
    int getsockname(sockaddr *addr, socklen_t *addrlen);
    int getpeername(sockaddr *addr, socklen_t *addrlen);
    int shutdown(int how);
    int getsockopt(int level, int optname, void *optval, socklen_t *optlen);
    int setsockopt(int level, int optname, const void *optval, socklen_t optlen);

    void ref()
    {
        refcount_inc(&refs);
    }

    bool ref_not_zero()
    {
        return refcount_inc_not_zero(&refs);
    }

    void unref()
    {
        if (refcount_dec_and_test(&refs))
            delete this;
    }

    void close()
    {
        unref();
    }

    void handle_backlog()
    {
    }

    void add_backlog(list_head *node)
    {
        list_add_tail(node, &socket_backlog);
    }
#endif
};

#define SOL_ICMP   800
#define SOL_TCP    6
#define SOL_UDP    21
#define SOL_ICMPV6 58

// Internal representations of the shutdown state of the socket
#define SHUTDOWN_RD   (1 << 0)
#define SHUTDOWN_WR   (1 << 1)
#define SHUTDOWN_RDWR (SHUTDOWN_RD | SHUTDOWN_WR)

#ifdef __cplusplus
template <typename T>
void cpp_destroy(struct socket *sock)
{
    ((T *) sock)->~T();
}

template <typename T>
int cpp_listen(struct socket *sock)
{
    return ((T *) sock)->listen();
}

template <typename T>
struct socket *cpp_accept(struct socket *sock, int flags)
{
    return ((T *) sock)->accept(flags);
}

template <typename T>
int cpp_bind(struct socket *sock, struct sockaddr *addr, socklen_t addrlen)
{
    return ((T *) sock)->bind(addr, addrlen);
}

template <typename T>
int cpp_connect(struct socket *sock, struct sockaddr *addr, socklen_t addrlen, int flags)
{
    return ((T *) sock)->connect(addr, addrlen, flags);
}

template <typename T>
ssize_t cpp_sendmsg(struct socket *sock, const struct kernel_msghdr *msg, int flags)
{
    return ((T *) sock)->sendmsg(msg, flags);
}

template <typename T>
ssize_t cpp_recvmsg(struct socket *sock, struct kernel_msghdr *msg, int flags)
{
    return ((T *) sock)->recvmsg(msg, flags);
}
template <typename T>
int cpp_getsockname(struct socket *sock, struct sockaddr *addr, socklen_t *addrlen)
{
    return ((T *) sock)->getsockname(addr, addrlen);
}

template <typename T>
int cpp_getpeername(struct socket *sock, struct sockaddr *addr, socklen_t *addrlen)
{
    return ((T *) sock)->getpeername(addr, addrlen);
}

template <typename T>
int cpp_shutdown(struct socket *sock, int how)
{
    return ((T *) sock)->shutdown(how);
}

template <typename T>
int cpp_getsockopt(struct socket *sock, int level, int optname, void *optval, socklen_t *optlen)
{
    return ((T *) sock)->getsockopt(level, optname, optval, optlen);
}

template <typename T>
int cpp_setsockopt(struct socket *sock, int level, int optname, const void *optval,
                   socklen_t optlen)
{
    return ((T *) sock)->setsockopt(level, optname, optval, optlen);
}

template <typename T>
void cpp_close(struct socket *sock)
{
    return ((T *) sock)->close();
}

template <typename T>
void cpp_handle_backlog(struct socket *sock)
{
    return ((T *) sock)->handle_backlog();
}

template <typename T>
short cpp_poll(struct socket *sock, void *poll_file, short events)
{
    return ((T *) sock)->poll(poll_file, events);
}

#define DEFINE_CPP_SOCKET_OPS(name, type)           \
    const struct socket_ops name = {                \
        .destroy = cpp_destroy<type>,               \
        .listen = cpp_listen<type>,                 \
        .accept = cpp_accept<type>,                 \
        .bind = cpp_bind<type>,                     \
        .connect = cpp_connect<type>,               \
        .sendmsg = cpp_sendmsg<type>,               \
        .recvmsg = cpp_recvmsg<type>,               \
        .getsockname = cpp_getsockname<type>,       \
        .getpeername = cpp_getpeername<type>,       \
        .shutdown = cpp_shutdown<type>,             \
        .getsockopt = cpp_getsockopt<type>,         \
        .setsockopt = cpp_setsockopt<type>,         \
        .close = cpp_close<type>,                   \
        .handle_backlog = cpp_handle_backlog<type>, \
        .poll = cpp_poll<type>,                     \
    }
#endif

__BEGIN_CDECLS

void socket_init(struct socket *socket);
int sock_default_listen(struct socket *sock);
struct socket *sock_default_accept(struct socket *sock, int flags);
int sock_default_bind(struct socket *sock, struct sockaddr *addr, socklen_t addrlen);
int sock_default_connect(struct socket *sock, struct sockaddr *addr, socklen_t addrlen, int flags);
ssize_t sock_default_sendmsg(struct socket *sock, const struct kernel_msghdr *msg, int flags);
ssize_t sock_default_recvmsg(struct socket *sock, struct kernel_msghdr *msg, int flags);
int sock_default_getsockname(struct socket *sock, struct sockaddr *addr, socklen_t *addrlen);
int sock_default_getpeername(struct socket *sock, struct sockaddr *addr, socklen_t *addrlen);
int sock_default_shutdown(struct socket *sock, int how);
void sock_default_close(struct socket *sock);
short sock_default_poll(struct socket *sock, void *poll_file, short events);
int getsockopt_socket_level(struct socket *sock, int optname, void *optval, socklen_t *optlen);
int setsockopt_socket_level(struct socket *sock, int optname, const void *optval, socklen_t optlen);

static inline bool sock_may_write(struct socket *sock)
{
    return READ_ONCE(sock->sk_send_queued) < READ_ONCE(sock->sk_sndbuf);
}

static inline int sock_write_space(struct socket *sock)
{
    return READ_ONCE(sock->sk_sndbuf) - READ_ONCE(sock->sk_send_queued);
}

static inline bool sock_charge_snd_bytes(struct socket *sock, unsigned int bytes)
{
    unsigned int queued = READ_ONCE(sock->sk_send_queued), new_space, expected;
    do
    {
        expected = queued;
        new_space = queued + bytes;
        if (new_space > sock->sk_sndbuf)
            return false;
        queued = cmpxchg_relaxed(&sock->sk_send_queued, expected, new_space);
    } while (queued != expected);
    return true;
}

static inline bool sock_charge_pbf(struct socket *sock, struct packetbuf *pbf)
{
    return sock_charge_snd_bytes(sock, pbf->total_len);
}

static inline void sock_discharge_snd_bytes(struct socket *sock, unsigned int bytes)
{
    unsigned int queued = READ_ONCE(sock->sk_send_queued), new_space, expected;
    do
    {
        expected = queued;
        new_space = queued - bytes;
        WARN_ON(queued < new_space);
        queued = cmpxchg_relaxed(&sock->sk_send_queued, expected, new_space);
    } while (queued != expected);

    sock->sock_ops->write_space(sock);
}

static inline void sock_discharge_pbf(struct socket *sock, struct packetbuf *pbf)
{
    sock_discharge_snd_bytes(sock, pbf->total_len);
}

static inline bool sock_charge_rmem_bytes(struct socket *sock, unsigned int bytes)
{
    unsigned int queued = READ_ONCE(sock->sk_rmem), new_space, expected;
    do
    {
        expected = queued;
        new_space = queued + bytes;
        if (new_space > sock->sk_sndbuf)
            return false;
        queued = cmpxchg_relaxed(&sock->sk_rmem, expected, new_space);
    } while (queued != expected);
    return true;
}

static inline bool sock_charge_rmem_pbf(struct socket *sock, struct packetbuf *pbf)
{
    return sock_charge_rmem_bytes(sock, pbf->total_len);
}

static inline void sock_discharge_rmem_bytes(struct socket *sock, unsigned int bytes)
{
    unsigned int queued = READ_ONCE(sock->sk_rmem), new_space, expected;
    do
    {
        expected = queued;
        new_space = queued - bytes;
        WARN_ON(queued < new_space);
        queued = cmpxchg_relaxed(&sock->sk_rmem, expected, new_space);
    } while (queued != expected);
}

static inline void sock_discharge_rmem_pbf(struct socket *sock, struct packetbuf *pbf)
{
    sock_discharge_rmem_bytes(sock, pbf->total_len);
}

int sock_stream_error(struct socket *sock, int err, int flags);

__END_CDECLS

#endif
