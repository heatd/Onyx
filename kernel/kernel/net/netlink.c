/*
 * Copyright (c) 2025 - 2026 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#define DEFINE_CURRENT
#include <stdio.h>

#include <onyx/mm/slab.h>
#include <onyx/net/netlink.h>
#include <onyx/net/socket.h>
#include <onyx/poll.h>
#include <onyx/process.h>
#include <onyx/random.h>

#include <linux/lockdep.h>

#define NLHASH_SIZE 16
static struct slab_cache *nlsock_cachep;
static struct list_head nlhash[NLHASH_SIZE];
static DEFINE_SPINLOCK(nlhash_lock);

static inline unsigned int nl_pid_hash(pid_t pid)
{
    return pid & (NLHASH_SIZE - 1);
}

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

int nl_done(struct packetbuf *pbf, pid_t pid, u32 seq, int err)
{
    struct nlmsghdr *hdr;

    hdr = nl_put(pbf, pid, seq, NLMSG_DONE, 0, sizeof(int));
    if (!hdr)
        return -ENOMEM;
    *(int *) NLMSG_DATA(hdr) = err;
    return 0;
}

static void netlink_destroy(struct socket *sock)
{
    struct netlink_sock *nlsk = (struct netlink_sock *) sock;
    struct packetbuf *pbf, *next;

    if (sock->bound)
    {
        spin_lock(&nlhash_lock);
        list_remove(&nlsk->bind_node);
        spin_unlock(&nlhash_lock);
    }

    list_for_each_entry_safe (pbf, next, &nlsk->buf_list, list_node)
    {
        list_remove(&pbf->list_node);
        pbf_put_ref(pbf);
    }
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
    struct nl_extack extack = {};
    if (nlsk->sock.proto == NETLINK_ROUTE)
        do_rtnetlink_send(nlsk, pbf, &extack);
}

void netlink_ack(struct netlink_sock *nlsk, struct packetbuf *in_pbf, struct nlmsghdr *msg, int err,
                 struct nl_extack *extack)
{
    struct packetbuf *pbf;
    bool wants_req = err != 0;
    struct nlmsghdr *new_msg;
    struct nlmsgerr *msgerr;
    size_t size;

    pbf = pbf_alloc_sk(GFP_KERNEL, &nlsk->sock, PAGE_SIZE);
    if (!pbf)
        return;

    size = sizeof(*msg);
    if (wants_req)
        size = msg->nlmsg_len;

    new_msg = nl_put(pbf, nlsk->pid, msg->nlmsg_seq, NLMSG_ERROR, wants_req ? 0 : NLM_F_CAPPED,
                     size + sizeof(int));
    if (!new_msg)
        goto err;
    msgerr = NLMSG_DATA(new_msg);
    msgerr->error = err;
    memcpy(&msgerr->msg, msg, sizeof(*msg));
    if (wants_req)
        memcpy(msg + 1, in_pbf->data, msg->nlmsg_len - sizeof(*msg));
    WARN_ON(extack->msg);
    list_add_tail(&pbf->list_node, &nlsk->buf_list);
    wait_queue_wake_all(&nlsk->wq);
    return;
err:
    pbf_free(pbf);
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

static void nl_fill_name(struct kernel_msghdr *msg)
{
    struct sockaddr_nl *nladdr = (struct sockaddr_nl *) msg->msg_name;

    nladdr->nl_family = AF_NETLINK;
    nladdr->nl_groups = 0;
    nladdr->nl_pad = 0;
    nladdr->nl_pid = 0;
    if (msg->msg_namelen > sizeof(*nladdr))
        msg->msg_namelen = sizeof(*nladdr);
}

static ssize_t netlink_recvmsg(struct socket *sock_, struct kernel_msghdr *msg, int flags)
{
    ssize_t ret = 0;
    unsigned int pbuf_len;
    struct iovec_iter *iter = msg->msg_iter;
    struct packetbuf *pbf;
    struct netlink_sock *sock = (struct netlink_sock *) sock_;

    hybrid_lock(&sock_->socket_lock);

    if (sock_->sock_err)
    {
        ret = sock_->sock_err;
        sock_->sock_err = 0;
        goto out_unlock;
    }

    if (list_is_empty(&sock->buf_list) && (flags & MSG_DONTWAIT))
    {
        ret = -EWOULDBLOCK;
        goto out_unlock;
    }

    ret = wait_for_event_socklocked_interruptible_2(&sock->wq, !list_is_empty(&sock->buf_list),
                                                    sock_);
    if (ret)
        goto out_unlock;

    pbf = list_first_entry(&sock->buf_list, struct packetbuf, list_node);
    if (!pbf)
        goto out_unlock;

    pbuf_len = pbf_length(pbf);
    ret = copy_from_pbf(pbf, iter, flags & MSG_PEEK ? PBF_COPY_ITER_PEEK : 0);
    if (ret < 0)
        goto out_unlock;

    if (ret != pbuf_len)
    {
        if (flags & MSG_TRUNC)
            ret = pbuf_len;
        msg->msg_flags |= MSG_TRUNC;
    }

    if (!(flags & MSG_PEEK))
    {
        list_remove(&pbf->list_node);
        pbf_put_ref(pbf);
    }

    if (msg->msg_name)
        nl_fill_name(msg);

    msg->msg_controllen = 0;
out_unlock:
    __unlock_sock(&sock_->socket_lock, sock_);
    return ret;
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

static bool validate_nladdr(const struct sockaddr_nl *nladdr, socklen_t addrlen)
{
    if (addrlen != sizeof(*nladdr))
        return false;
    if (nladdr->nl_family != AF_NETLINK)
        return false;
    if (nladdr->nl_pad != 0)
        return false;
    return true;
}

static struct netlink_sock *nl_find_socket(pid_t pid)
{
    struct netlink_sock *sock;

    lockdep_assert_held(&nlhash_lock);
    list_for_each_entry (sock, &nlhash[nl_pid_hash(pid)], bind_node)
    {
        if (sock->pid == pid)
            return sock;
    }

    return NULL;
}

static pid_t nl_allocate_pid(void)
{
    pid_t pid = current->pid_;
    int i;

    lockdep_assert_held(&nlhash_lock);
    /* First, default to current->pid. If this is already used, then use a pseudo-random function
     * over the negative range of ints to find a port. Avoid the negative errno space. */
    if (!nl_find_socket(pid))
        return pid;

    for (;;)
    {
        spin_unlock(&nlhash_lock);
        do
        {
            pid = arc4random();
        } while (pid > -MAX_ERRNO);
        spin_lock(&nlhash_lock);
        /* Try a couple of pids in a row */
        for (i = 0; i < 10; i++)
        {
            if (!nl_find_socket(pid + i))
                return pid + i;
        }
    }
}

static int netlink_bind(struct socket *sock, struct sockaddr *addr, socklen_t addrlen)
{
    struct sockaddr_nl *nladdr = (struct sockaddr_nl *) addr;
    struct netlink_sock *nlsk;
    int err;

    if (!validate_nladdr(nladdr, addrlen))
        return -EINVAL;

    spin_lock(&nlhash_lock);

    err = -EADDRINUSE;
    if (nladdr->nl_pid != 0)
    {
        /* We have a specific pid that is desired. Check if it's not already bound. */
        if (nl_find_socket(nladdr->nl_pid))
            goto out;
    }
    else
        nladdr->nl_pid = nl_allocate_pid();

    nlsk = container_of(sock, struct netlink_sock, sock);
    nlsk->pid = nladdr->nl_pid;
    nlsk->groups = nladdr->nl_groups;
    list_add_tail(&nlsk->bind_node, &nlhash[nl_pid_hash(nlsk->pid)]);
    err = 0;
    sock->bound = true;
    /* TODO: handle groups */
out:
    spin_unlock(&nlhash_lock);
    return err;
}

static int netlink_getsockname(struct socket *sock, struct sockaddr *addr, socklen_t *addrlen)
{
    struct netlink_sock *nlsk = (struct netlink_sock *) sock;
    struct sockaddr_nl *nladdr = (struct sockaddr_nl *) addr;
    int err = -EINVAL;

    hybrid_lock(&sock->socket_lock);
    if (!sock->bound)
        goto out;

    *addrlen = sizeof(struct sockaddr_nl);
    nladdr->nl_family = AF_NETLINK;
    nladdr->nl_pad = 0;
    nladdr->nl_pid = nlsk->pid;
    nladdr->nl_groups = nlsk->groups;
    err = 0;
out:
    __unlock_sock(&sock->socket_lock, sock);
    return err;
}

static const struct socket_ops netlink_ops = {
    .destroy = netlink_destroy,
    .listen = sock_default_listen,
    .accept = sock_default_accept,
    .bind = netlink_bind,
    .connect = sock_default_connect,
    .sendmsg = netlink_sendmsg,
    .recvmsg = netlink_recvmsg,
    .getsockname = netlink_getsockname,
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
    nlsock->pid = 0;
    nlsock->groups = 0;
    return &nlsock->sock;
}

__init void netlink_init(void)
{
    nlsock_cachep = kmem_cache_create("netlink_sock", sizeof(struct netlink_sock),
                                      _Alignof(struct netlink_sock), KMEM_CACHE_PANIC, NULL);
    for (int i = 0; i < NLHASH_SIZE; i++)
        INIT_LIST_HEAD(&nlhash[i]);
}
