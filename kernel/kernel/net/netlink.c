/*
 * Copyright (c) 2025 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <stdio.h>

#include <onyx/mm/slab.h>
#include <onyx/net/netlink.h>
#include <onyx/net/socket.h>
#include <onyx/poll.h>

static struct slab_cache *nlsock_cachep;

struct nlmsghdr *nl_put(struct packetbuf *pbf, pid_t pid, u32 seq, u16 type, u16 flags, u32 len)
{
    struct nlmsghdr *nlh;
    unsigned int total;

    total = len + sizeof(*nlh);
    nlh = pbf_put(pbf, NLMSG_ALIGN(total));
    if (!nlh)
        return NULL;

    nlh->nlmsg_flags = flags;
    nlh->nlmsg_pid = pid;
    nlh->nlmsg_seq = seq;
    nlh->nlmsg_type = type;
    nlh->nlmsg_len = total;

    if (NLMSG_ALIGN(total) > total)
    {
        /* Had to pad, zero the tail */
        memset(NLMSG_DATA(nlh) + total, 0, NLMSG_ALIGN(total) - total);
    }

    return nlh;
}

static void netlink_destroy(struct socket *sock)
{
}

static int netlink_getsockopt(struct socket *sock, int level, int optname, void *val,
                              socklen_t *len)
{
    if (level == SOL_SOCKET)
        return getsockopt_socket_level(sock, optname, val, len);
    return -ENOPROTOOPT;
}

static int netlink_setsockopt(struct socket *sock, int level, int optname, const void *val,
                              socklen_t len)
{
    if (level == SOL_SOCKET)
        return setsockopt_socket_level(sock, optname, val, len);
    return -ENOPROTOOPT;
}

static void nl_pbf_dtor(struct packetbuf *pbf)
{
    sock_discharge_pbf(pbf->sock, pbf);
}

static void do_netlink_send(struct netlink_sock *nlsk, struct packetbuf *pbf)
{
    if (nlsk->sock.proto == NETLINK_ROUTE)
        do_rtnetlink_send(nlsk, pbf);
}

static ssize_t netlink_sendmsg(struct socket *sock, const struct kernel_msghdr *msg, int flags)
{
    struct packetbuf *pbf;
    ssize_t ret;

    ret = iovec_iter_bytes(msg->msg_iter);
    pbf = pbf_alloc_sk(GFP_KERNEL, sock, ret);
    if (!pbf)
        return -ENOMEM;

    ret = copy_from_iter(msg->msg_iter, pbf_put(pbf, ret), ret);
    if (ret < 0)
    {
        pbf_free(pbf);
        return -EFAULT;
    }

    if (!sock_charge_pbf(sock, pbf))
    {
        /* Failed to charge write space, stop. */
        pbf_free(pbf);
        return -ENOBUFS;
    }

    pbf->dtor = nl_pbf_dtor;
    do_netlink_send((struct netlink_sock *) sock, pbf);
    pbf_put_ref(pbf);
    return ret;
}

static ssize_t netlink_recvmsg(struct socket *sock_, struct kernel_msghdr *msg, int flags)
{
    size_t bytes_read = 0;
    unsigned int pbuf_len;
    struct iovec_iter *iter = msg->msg_iter;
    struct packetbuf *pbf, *next;
    struct netlink_sock *sock = (struct netlink_sock *) sock_;

    hybrid_lock(&sock_->socket_lock);

    if (sock_->sock_err)
    {
        bytes_read = sock_->sock_err;
        sock_->sock_err = 0;
        goto out_unlock;
    }

    bytes_read = wait_for_event_socklocked_interruptible_2(&sock->wq,
                                                           !list_is_empty(&sock->buf_list), sock_);
    if (bytes_read)
        goto out_unlock;

    list_for_each_entry_safe (pbf, next, &sock->buf_list, list_node)
    {
        if (iovec_iter_empty(iter))
        {
            msg->msg_flags |= MSG_TRUNC;
            break;
        }

        pbuf_len = pbf_length(pbf);

        ssize_t read = copy_from_pbf(pbf, iter, flags & MSG_PEEK ? PBF_COPY_ITER_PEEK : 0);
        if (read < 0)
        {
            if (bytes_read == 0)
                bytes_read = read;
            break;
        }

        bytes_read += read;
        if (read != pbuf_len)
            break;

        if (!(flags & MSG_PEEK))
        {
            list_remove(&pbf->list_node);
            pbf_put_ref(pbf);
        }
    }

    msg->msg_controllen = 0;
out_unlock:
    __unlock_sock(&sock_->socket_lock, sock_);
    return bytes_read;
}

static short netlink_poll(struct socket *sock, void *poll_file, short events)
{
    struct netlink_sock *nlsk = (struct netlink_sock *) sock;
    short avail_events = 0;

    hybrid_lock(&sock->socket_lock);

    if (sock_may_write(sock))
        avail_events |= POLLOUT;

    if (events & POLLIN)
    {
        if (!list_is_empty(&nlsk->buf_list))
            avail_events |= POLLIN;
        else
            poll_wait_helper(poll_file, &nlsk->wq);
    }

    __unlock_sock(&sock->socket_lock, sock);
    return avail_events & events;
}

static const struct socket_ops netlink_ops = {
    .destroy = netlink_destroy,
    .listen = sock_default_listen,
    .accept = sock_default_accept,
    .bind = sock_default_bind,
    .connect = sock_default_connect,
    .sendmsg = netlink_sendmsg,
    .recvmsg = netlink_recvmsg,
    .getsockname = sock_default_getsockname,
    .getpeername = sock_default_getpeername,
    .getsockopt = netlink_getsockopt,
    .setsockopt = netlink_setsockopt,
    .shutdown = sock_default_shutdown,
    .close = sock_default_close,
    .poll = netlink_poll,
};

struct socket *netlink_create_socket(int type)
{
    struct netlink_sock *nlsock;

    nlsock = kmem_cache_alloc(nlsock_cachep, GFP_KERNEL);
    if (!nlsock)
        return NULL;

    socket_init(&nlsock->sock);
    nlsock->sock.type = type;
    nlsock->sock.sock_ops = &netlink_ops;
    init_wait_queue_head(&nlsock->wq);
    INIT_LIST_HEAD(&nlsock->buf_list);
    return &nlsock->sock;
}

__init void netlink_init(void)
{
    nlsock_cachep = kmem_cache_create("netlink_sock", sizeof(struct netlink_sock),
                                      _Alignof(struct netlink_sock), KMEM_CACHE_PANIC, NULL);
}
