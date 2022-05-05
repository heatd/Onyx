/*
 * Copyright (c) 2018 - 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
#include <errno.h>
#include <net/if.h>
#include <sys/ioctl.h>

#include <onyx/dentry.h>
#include <onyx/file.h>
#include <onyx/net/ip.h>
#include <onyx/net/netkernel.h>
#include <onyx/net/socket.h>
#include <onyx/poll.h>
#include <onyx/scoped_lock.h>
#include <onyx/utils.h>

socket *file_to_socket(struct file *f)
{
    return static_cast<socket *>(f->f_ino->i_helper);
}

socket *file_to_socket(auto_file &f)
{
    return file_to_socket(f.get_file());
}

/* Most of these default values don't make much sense, but we have them as placeholders */
int socket::listen()
{
    return 0;
}

socket *socket::accept(socket_conn_request *req)
{
    (void) req;
    return errno = EIO, nullptr;
}

int socket::bind(struct sockaddr *addr, socklen_t addrlen)
{
    (void) addr;
    (void) addrlen;
    return -EIO;
}

int socket::connect(struct sockaddr *addr, socklen_t addrlen, int flags)
{
    (void) addr;
    (void) addrlen;
    return -EIO;
}

ssize_t socket::sendmsg(const struct msghdr *msg, int flags)
{
    (void) msg;
    (void) flags;
    return -EIO;
}

int socket::getsockname(sockaddr *addr, socklen_t *addrlen)
{
    (void) addr;
    (void) addrlen;
    return -EOPNOTSUPP;
}

int socket::getpeername(sockaddr *addr, socklen_t *addrlen)
{
    (void) addr;
    (void) addrlen;
    return -EOPNOTSUPP;
}

int socket::shutdown(int how)
{
    shutdown_state = how;
    return 0;
}

ssize_t recv_queue::recvfrom(void *_buf, size_t len, int flags, sockaddr *src_addr, socklen_t *slen)
{
    char *buf = (char *) _buf;
    bool storing_src = src_addr != nullptr;
    bool remove_data = !(flags & MSG_PEEK);
    ssize_t total_read = 0;

    int st = 0;

    auto list = get_recv_packet_list(flags, len, st);
    if (!list)
    {
        return st;
    }

    list_for_every_safe (&recv_list)
    {
        auto packet = list_head_cpp<recv_packet>::self_from_list_head(l);

        if (storing_src)
        {
            // printk("packet src: %u\n", ((sockaddr_in *) &packet->src_addr)->sin_addr.s_addr);
            if (copy_to_user(src_addr, &packet->src_addr, packet->addr_len) < 0)
            {
                spin_unlock(&recv_queue_lock);
                return -EFAULT;
            }

            socklen_t length = packet->addr_len;
            if (copy_to_user(slen, &length, sizeof(socklen_t)) < 0)
            {
                spin_unlock(&recv_queue_lock);
                return -EFAULT;
            }

            /* don't store src twice. Although I'm not sure how defined storing_src is with
             * !SOCK_DGRAM */
            storing_src = false;
        }

        auto avail = packet->size - packet->read;

        ssize_t to_copy = min(len, avail);

        if (copy_to_user(buf, (char *) packet->payload + packet->read, to_copy) < 0)
        {
            spin_unlock(&recv_queue_lock);
            return -EFAULT;
        }

        buf += to_copy;
        total_read += to_copy;
        len -= to_copy;

        if (remove_data)
        {
            packet->read += to_copy;
            total_data_in_buffers -= to_copy;

            if (packet->read == packet->size || sock->type == SOCK_DGRAM)
            {
                total_data_in_buffers -= packet->size - packet->read;
                list_remove(&packet->list_node);
                delete packet;
            }
        }

        if (total_read == (ssize_t) len || sock->type == SOCK_DGRAM)
            break;
    }

    spin_unlock(&recv_queue_lock);

    return total_read;
}

void recv_queue::clear_packets()
{
    scoped_lock guard{recv_queue_lock};

    list_for_every_safe (&recv_list)
    {
        auto packet = list_head_cpp<recv_packet>::self_from_list_head(l);
        list_remove(&packet->list_node);
        total_data_in_buffers -= (packet->size - packet->read);
        delete packet;
    }
}

recv_queue::~recv_queue()
{
    clear_packets();

    assert(total_data_in_buffers == 0);
}

bool recv_queue::has_data_available(int msg_flags, size_t required_data)
{
    if (msg_flags & MSG_WAITALL)
    {
        return total_data_in_buffers >= required_data;
    }

    return !list_is_empty(&recv_list);
}

bool recv_queue::poll(void *poll_file)
{
    scoped_lock guard{recv_queue_lock};

    if (has_data_available(0, 0))
        return true;

    poll_wait_helper(poll_file, &recv_wait);
    return false;
}

/* Returns with recv_queue_lock held on success */
struct list_head *recv_queue::get_recv_packet_list(int msg_flags, size_t required_data, int &error)
{
    spin_lock(&recv_queue_lock);

    if (msg_flags & MSG_DONTWAIT && !has_data_available(msg_flags, required_data))
    {
        spin_unlock(&recv_queue_lock);
        error = -EAGAIN;
        return nullptr;
    }

    /* TODO: Add recv timeout support */
    error = wait_for_event_locked_interruptible(
        &recv_wait, has_data_available(msg_flags, required_data), &recv_queue_lock);
    if (error == 0)
    {
        return &recv_list;
    }
    else
    {
        spin_unlock(&recv_queue_lock);
        return nullptr;
    }
}

int fd_flags_to_msg_flags(struct file *f)
{
    int flags = 0;
    if (f->f_flags & O_NONBLOCK)
        flags |= MSG_DONTWAIT;
    return flags;
}

void recv_queue::add_packet(recv_packet *p)
{
    scoped_lock guard{recv_queue_lock};

    list_add_tail(&p->list_node, &recv_list);
    total_data_in_buffers += p->size;
    wait_queue_wake_all(&recv_wait);
}

ssize_t socket::recvmsg(struct msghdr *msg, int flags)
{
    return -EIO;
}

size_t socket_write(size_t offset, size_t len, void *buffer, struct file *file)
{
    socket *s = file_to_socket(file);

    msghdr msg;
    msg.msg_control = nullptr;
    msg.msg_controllen = 0;
    msg.msg_flags = 0;

    iovec vec0;
    /* This cast is safe because sendmsg won't write to the iov */
    vec0.iov_base = const_cast<void *>(buffer);
    vec0.iov_len = len;
    msg.msg_iov = &vec0;
    msg.msg_iovlen = 1;
    msg.msg_name = nullptr;
    msg.msg_namelen = 0;

    ssize_t res = s->sendmsg(&msg, fd_flags_to_msg_flags(file));
    if (res < 0)
        return errno = -res, -1;
    return res;
}

size_t socket_read(size_t offset, size_t len, void *buffer, file *file)
{
    socket *s = file_to_socket(file);
    msghdr msg;
    msg.msg_control = nullptr;
    msg.msg_controllen = 0;
    msg.msg_flags = 0;

    iovec vec0;
    /* This cast is safe because sendmsg won't write to the iov */
    vec0.iov_base = buffer;
    vec0.iov_len = len;
    msg.msg_iov = &vec0;
    msg.msg_iovlen = 1;
    msg.msg_name = nullptr;
    msg.msg_namelen = 0;

    ssize_t res = s->recvmsg(&msg, fd_flags_to_msg_flags(file));

    if (res < 0)
        return errno = -res, -1;
    return res;
}

short socket::poll(void *poll_file, short events)
{
    short avail_events = POLLOUT;

    if (events & POLLPRI)
    {
        if (oob_data_queue.poll(poll_file))
            avail_events |= POLLPRI;
    }

    if (events & POLLIN)
    {
        if (in_band_queue.poll(poll_file))
            avail_events |= POLLIN;
    }

    // printk("avail events: %u\n", avail_events);

    return avail_events & events;
}

short socket_poll(void *poll_file, short events, struct file *node)
{
    socket *s = file_to_socket(node);

#if 0
	if(s->s_ops->poll)
		return s->s_ops->poll(poll_file, events, s);
#endif
    return s->poll(poll_file, events);
}

void socket_close(struct inode *ino);

int do_siocgifname(struct ifreq *req)
{
    struct ifreq r;
    if (copy_from_user(&r, req, sizeof(r)) < 0)
        return -EFAULT;

    auto nif = netif_from_if(r.ifr_ifindex);

    if (!nif)
        return -ENXIO;

    strlcpy(r.ifr_ifrn.ifrn_name, nif->name, IF_NAMESIZE);

    return copy_to_user(req, &r, sizeof(r));
}

int do_siocgifconf(struct ifconf *uconf)
{
    struct ifconf conf;

    if (copy_from_user(&conf, uconf, sizeof(conf)) < 0)
        return -EFAULT;

    size_t n_entries = conf.ifc_len / sizeof(conf);

    const auto &netif_list = netif_lock_and_get_list();
    int off = 0;

    for (auto &nif : netif_list)
    {
        // only exit on n_entries == 0 if we're actually copying stuff
        if (conf.ifc_buf && n_entries == 0)
            break;

        if (!nif->local_ip.sin_addr.s_addr)
            continue;

        struct ifreq req;

        char *ubuf = conf.ifc_buf + off;

        if (conf.ifc_buf == nullptr)
        {
            // We're only getting the number of bytes we need
            off += sizeof(struct ifreq);
            continue;
        }

        if (copy_from_user(&req, conf.ifc_buf + off, sizeof(req)) < 0)
        {
            netif_unlock_list();
            return -EFAULT;
        }

        // We only return AF_INET addresses because of compatibility issues
        sockaddr_in in;
        in.sin_family = AF_INET;
        in.sin_port = 0;
        memset(in.sin_zero, 0, sizeof(in.sin_zero));
        in.sin_addr.s_addr = nif->local_ip.sin_addr.s_addr;
        memcpy(&req.ifr_addr, &in, sizeof(in));

        strlcpy(req.ifr_name, nif->name, IF_NAMESIZE);

        if (copy_to_user(ubuf, &req, sizeof(req)) < 0)
        {
            netif_unlock_list();
            return -EFAULT;
        }

        off += sizeof(struct ifreq);
        n_entries--;
    }

    conf.ifc_len = off;

    netif_unlock_list();

    return copy_to_user(uconf, &conf, sizeof(conf));
}

unsigned int do_siocgifaddr(struct ifreq *ureq)
{
    struct ifreq req;
    if (copy_from_user(&req, ureq, sizeof(req)) < 0)
        return -EFAULT;

    // Make sure the name is null terminated
    req.ifr_name[IFNAMSIZ - 1] = '\0';

    auto nif = netif_from_name(req.ifr_name);

    if (!nif)
        return -ENODEV;

    if (nif->local_ip.sin_addr.s_addr == 0)
        return -EADDRNOTAVAIL;

    sockaddr_in in;
    in.sin_family = AF_INET;
    in.sin_port = 0;
    memset(in.sin_zero, 0, sizeof(in.sin_zero));
    in.sin_addr.s_addr = nif->local_ip.sin_addr.s_addr;

    memcpy(&req.ifr_addr, &in, sizeof(in));

    return copy_to_user(ureq, &req, sizeof(req));
}

unsigned int do_siocsifaddr(struct ifreq *ureq)
{
    struct ifreq req;
    if (copy_from_user(&req, ureq, sizeof(req)) < 0)
        return -EFAULT;

    // Make sure the name is null terminated
    req.ifr_name[IFNAMSIZ - 1] = '\0';

    auto nif = netif_from_name(req.ifr_name);

    if (!nif)
        return -ENODEV;

    sockaddr_in in;
    memcpy(&in, &req.ifr_addr, sizeof(in));

    if (in.sin_family != AF_INET)
        return -EINVAL;

    nif->local_ip.sin_addr.s_addr = in.sin_addr.s_addr;

    memcpy(&req.ifr_addr, &in, sizeof(in));

    return copy_to_user(ureq, &req, sizeof(req));
}

unsigned int socket_ioctl(int request, void *argp, struct file *file)
{
    switch (request)
    {
        case FIONBIO: {
            int on;

            if (copy_from_user(&on, argp, sizeof(on)) < 0)
                return -EFAULT;

            if (on)
                file->f_flags |= O_NONBLOCK;
            else
                file->f_flags &= ~O_NONBLOCK;

            return 0;
        }

        case SIOCGIFNAME: {
            return do_siocgifname((struct ifreq *) argp);
        }

        case SIOCGIFCONF: {
            return do_siocgifconf((struct ifconf *) argp);
        }

        case SIOCGIFADDR: {
            return do_siocgifaddr((struct ifreq *) argp);
        }

        case SIOCSIFADDR: {
            return do_siocsifaddr((struct ifreq *) argp);
        }
    }

    return -ENOTTY;
}

struct file_ops socket_ops = {
    .read = socket_read,
    .write = socket_write,
    .close = socket_close,
    .ioctl = socket_ioctl,
    .poll = socket_poll,
};

auto_file get_socket_fd(int fd)
{
    struct file *desc = get_file_description(fd);
    if (!desc)
        return errno = EBADF, nullptr;

    if (desc->f_ino->i_fops->write != socket_write)
    {
        fd_put(desc);
        return errno = ENOTSOCK, nullptr;
    }

    return desc;
}

int sys_connect(int sockfd, const struct sockaddr *uaddr, socklen_t addrlen)
{
    sockaddr_storage addr;
    if (addrlen > sizeof(sockaddr_storage))
        return -EINVAL;

    if (copy_from_user(&addr, uaddr, addrlen) < 0)
        return -EFAULT;

    auto desc = get_socket_fd(sockfd);
    if (!desc)
        return -errno;

    int ret = -EINTR;
    socket *s = file_to_socket(desc.get_file());

    s->socket_lock.lock();

    if (s->connected)
    {
        ret = -EISCONN;
        goto out2;
    }

    ret = s->connect((sockaddr *) &addr, addrlen, desc.get_file()->f_flags);

out2:
    s->socket_lock.unlock();
    return ret;
}

int sys_bind(int sockfd, const struct sockaddr *uaddr, socklen_t addrlen)
{
    sockaddr_storage addr;
    if (addrlen > sizeof(sockaddr_storage))
        return -EINVAL;

    if (copy_from_user(&addr, uaddr, addrlen) < 0)
        return -EFAULT;

    auto desc = get_socket_fd(sockfd);
    if (!desc)
        return -errno;

    socket *s = file_to_socket(desc.get_file());
    int ret = -EINTR;

    s->socket_lock.lock();

    if (s->bound)
    {
        ret = -EINVAL;
        goto out2;
    }

    ret = s->bind((sockaddr *) &addr, addrlen);

out2:
    s->socket_lock.unlock();
    return ret;
}

ssize_t sys_recvfrom(int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr,
                     socklen_t *paddrlen)
{
    auto_file desc = get_socket_fd(sockfd);
    if (!desc)
        return -errno;

    socket *s = file_to_socket(desc.get_file());

    flags |= fd_flags_to_msg_flags(desc.get_file());
    socklen_t addrlen = 0;

    sockaddr_storage sa;

    if (src_addr)
    {
        if (copy_from_user(&addrlen, paddrlen, sizeof(addrlen)) < 0)
            return -EFAULT;

        if (addrlen > sizeof(sa))
            return -EINVAL;

        if (copy_from_user(&sa, src_addr, addrlen) < 0)
            return -EFAULT;
    }

    msghdr msg;
    msg.msg_control = nullptr;
    msg.msg_controllen = 0;
    msg.msg_flags = 0;

    iovec vec0;
    /* This cast is safe because sendmsg won't write to the iov */
    vec0.iov_base = const_cast<void *>(buf);
    vec0.iov_len = len;
    msg.msg_iov = &vec0;
    msg.msg_iovlen = 1;
    msg.msg_name = src_addr ? &sa : nullptr;
    msg.msg_namelen = src_addr ? addrlen : 0;

    ssize_t ret = s->recvmsg(&msg, flags);

    if (ret < 0)
        return ret;

    if (src_addr)
    {
        if (copy_to_user(paddrlen, &msg.msg_namelen, sizeof(socklen_t)) < 0)
            return -EFAULT;

        if (copy_to_user(src_addr, msg.msg_name, msg.msg_namelen) < 0)
            return -EFAULT;
    }

    return ret;
}

#define BACKLOG_FOR_LISTEN_0 16
const int backlog_limit = 4096;

int sys_listen(int sockfd, int backlog)
{
    int st = 0;
    auto_file f = get_socket_fd(sockfd);
    if (!f)
        return -errno;

    socket *sock = file_to_socket(f.get_file());

    if (sock->type != SOCK_DGRAM || sock->type != SOCK_SEQPACKET)
    {
        st = -EOPNOTSUPP;
        goto out;
    }

    /* POSIX specifies that if backlog = 0, we can (and should) set the backlog value
     * to a implementation specified minimum
     */

    if (backlog == 0)
    {
        backlog = BACKLOG_FOR_LISTEN_0;
    }

    /* We should also set a backlog limit to stop DDOS attacks, and clamp the value */
    if (backlog > backlog_limit)
        backlog = backlog_limit;

    sock->socket_lock.lock();

    /* Big note: the backlog value in the socket structure is used both to determine
     * the backlog size **and** if the socket is in a listening state, with != 0 repre-
     * senting that state.
     */

    sock->backlog = backlog;

    if ((st = sock->listen()) < 0)
    {
        /* Don't forget to reset the backlog to 0 to show that it's not in a
         * listening state
         */
        sock->backlog = 0;
        goto out2;
    }

out2:
    sock->socket_lock.unlock();
out:
    return st;
}

int sys_shutdown(int sockfd, int how)
{
    auto_file f = get_socket_fd(sockfd);
    if (!f)
        return -errno;
    socket *sock = file_to_socket(f.get_file());

    if (how != SHUT_RD && how != SHUT_WR && how != SHUT_RDWR)
        return -EINVAL;

    int internal_how = 0;

    switch (how)
    {
        case SHUT_RD:
            internal_how = SHUTDOWN_RD;
            break;
        case SHUT_WR:
            internal_how = SHUTDOWN_WR;
            break;
        case SHUT_RDWR:
            internal_how = SHUTDOWN_RDWR;
            break;
    }

    return sock->shutdown(internal_how);
}

int check_af_support(int domain)
{
    switch (domain)
    {
        case AF_INET:
        case AF_UNIX:
        case AF_INET6:
        case AF_NETKERNEL:
            return 0;
        default:
            return -1;
    }
}

static const int type_mask = ~(SOCK_NONBLOCK | SOCK_CLOEXEC);
static const int sock_flag_mask = ~type_mask;

int net_check_type_support(int type)
{
    (void) sock_flag_mask;
    return 1;
}

int net_autodetect_protocol(int type, int domain)
{

    /* AF_NETKERNEL is an outlier since it's usable in both types */
    if (domain == AF_NETKERNEL)
        return NETKERNEL_PROTO;

    switch (type & type_mask)
    {
        case SOCK_DGRAM: {
            if (domain == AF_UNIX)
                return PROTOCOL_UNIX;
            else if (domain == AF_INET || domain == AF_INET6)
                return IPPROTO_UDP;
            else
                return -1;
        }

        case SOCK_RAW: {
            if (domain == AF_INET)
                return IPPROTO_IP;
            else if (domain == AF_INET6)
                return IPPROTO_IPV6;
            else if (domain == AF_UNIX)
                return PROTOCOL_UNIX;
            return -1;
        }

        case SOCK_STREAM: {
            if (domain == AF_INET || domain == AF_INET6)
                return IPPROTO_TCP;
            else
                return -1;
        }
    }

    return -1;
}

socket *unix_create_socket(int type, int protocol);

socket *socket_create(int domain, int type, int protocol)
{
    socket *socket = nullptr;

#ifdef CONFIG_NET
    switch (domain)
    {
        case AF_INET:
            socket = ip::v4::create_socket(type, protocol);
            break;
        case AF_INET6:
            socket = ip::v6::create_socket(type, protocol);
            break;
        case AF_UNIX:
            // socket = unix_create_socket(type, protocol);
            /* TODO: Fix unix sockets */
            socket = nullptr;
            break;
        case AF_NETKERNEL:
            socket = netkernel::create_socket(type);
            break;
        default:
            return errno = EAFNOSUPPORT, nullptr;
    }
#endif

    if (!socket)
        return nullptr;

    socket->type = type;
    socket->domain = domain;
    socket->proto = protocol;
    INIT_LIST_HEAD(&socket->conn_request_list);

    return socket;
}

void socket_close(struct inode *ino)
{
    socket *s = static_cast<socket *>(ino->i_helper);
    s->close();
}

struct inode *socket_create_inode(socket *socket)
{
    struct inode *inode = inode_create(false);

    if (!inode)
        return nullptr;

    inode->i_fops = &socket_ops;

    inode->i_type = VFS_TYPE_UNIX_SOCK;
    inode->i_flags = INODE_FLAG_NO_SEEK;
    inode->i_helper = socket;

    return inode;
}

file *socket_inode_to_file(inode *ino)
{
    auto f = inode_to_file(ino);
    if (!f)
        return nullptr;

    auto dent = dentry_create("<socket>", ino, nullptr);
    if (!dent)
    {
        fd_put(f);
        return nullptr;
    }

    f->f_dentry = dent;
    return f;
}

int sys_socket(int domain, int type, int protocol)
{
    int dflags;
    dflags = O_RDWR;

    if (check_af_support(domain) < 0)
        return -EAFNOSUPPORT;

    if (net_check_type_support(type) < 0)
        return -EINVAL;

    if (protocol == 0)
    {
        /* If protocol == 0, auto-detect the proto */
        if ((protocol = net_autodetect_protocol(type, domain)) < 0)
            return -EINVAL;
    }

    /* Create the socket */
    socket *socket = socket_create(domain, type & type_mask, protocol);
    if (!socket)
        return -errno;

    struct inode *inode = socket_create_inode(socket);
    if (!inode)
        return -errno;

    struct file *f = socket_inode_to_file(inode);
    if (!f)
    {
        close_vfs(inode);
        return -ENOMEM;
    }

    if (type & SOCK_CLOEXEC)
        dflags |= O_CLOEXEC;
    if (type & SOCK_NONBLOCK)
        dflags |= O_NONBLOCK;

    /* Open a file descriptor with the socket vnode */
    int fd = open_with_vnode(f, dflags);
    /* If we failed, close the socket and return */
    if (fd < 0)
        close_vfs(inode);
    fd_put(f);

    return fd;
}

#define ACCEPT4_VALID_FLAGS (SOCK_CLOEXEC | SOCK_NONBLOCK)

socket_conn_request *dequeue_conn_request(socket *sock)
{
    spin_lock(&sock->conn_req_list_lock);

    assert(list_is_empty(&sock->conn_request_list) == false);
    struct list_head *first_elem = list_first_element(&sock->conn_request_list);

    list_remove(first_elem);

    spin_unlock(&sock->conn_req_list_lock);

    socket_conn_request *req = container_of(first_elem, socket_conn_request, list_node);

    return req;
}

int sys_accept4(int sockfd, struct sockaddr *addr, socklen_t *slen, int flags)
{
    int st = 0;
    if (flags & ~ACCEPT4_VALID_FLAGS)
        return -EINVAL;

    auto f = get_socket_fd(sockfd);
    if (!f)
        return -errno;

    socket *sock = file_to_socket(f.get_file());
    socket_conn_request *req = nullptr;
    socket *new_socket = nullptr;
    inode *inode = nullptr;
    file *newf = nullptr;
    int dflags = 0, fd = -1;

    sock->socket_lock.lock();

    if (!sock->listening())
    {
        st = -EINVAL;
        goto out;
    }

    if (sock->type != SOCK_STREAM)
    {
        st = -EOPNOTSUPP;
        goto out;
    }

    sem_wait(&sock->listener_sem);

    req = dequeue_conn_request(sock);

    new_socket = sock->accept(req);
    free(req);

    if (!new_socket)
    {
        st = -errno;
        goto out;
    }

    inode = socket_create_inode(new_socket);
    if (!inode)
    {
        new_socket->unref();
        st = -errno;
        goto out;
    }

    newf = socket_inode_to_file(inode);
    if (!newf)
    {
        close_vfs(inode);
        st = -errno;
        goto out;
    }

    if (flags & SOCK_CLOEXEC)
        dflags |= O_CLOEXEC;

    /* Open a file descriptor with the socket vnode */
    fd = open_with_vnode(newf, dflags);

    fd_put(newf);

    st = fd;
out:
    sock->socket_lock.unlock();
    return st;
}

int sys_accept(int sockfd, struct sockaddr *addr, socklen_t *slen)
{
    return sys_accept4(sockfd, addr, slen, 0);
}

int socket::getsockopt_socket_level(int optname, void *optval, socklen_t *optlen)
{
    switch (optname)
    {
        /* TODO: Add more options */
        case SO_ACCEPTCONN: {
            int val = (int) listening();
            return put_option(val, optval, optlen);
        }

        case SO_DOMAIN: {
            return put_option(domain, optval, optlen);
        }

        case SO_ERROR: {
            auto err = sock_err;
            sock_err = 0;
            return put_option(err, optval, optlen);
        }

        case SO_TYPE: {
            return put_option(type, optval, optlen);
        }

        case SO_PROTOCOL: {
            return put_option(proto, optval, optlen);
        }

        case SO_RCVBUF: {
            return put_option(rx_max_buf, optval, optlen);
        }

        case SO_SNDBUF: {
            return put_option(tx_max_buf, optval, optlen);
        }

        case SO_REUSEADDR: {
            const int raddr = (int) reuse_addr;
            return put_option<int>(raddr, optval, optlen);
        }

        case SO_BROADCAST: {
            const int bcast_allowed = (int) broadcast_allowed;
            return put_option<int>(bcast_allowed, optval, optlen);
        }

        default:
            return -ENOPROTOOPT;
    }
}

int socket::setsockopt_socket_level(int optname, const void *optval, socklen_t optlen)
{
    switch (optname)
    {
        case SO_RCVBUF: {
            auto ex = get_socket_option<unsigned int>(optval, optlen);

            if (ex.has_error())
                return ex.error();

            rx_max_buf = ex.value();
            return 0;
        }

        case SO_SNDBUF: {
            auto ex = get_socket_option<unsigned int>(optval, optlen);

            if (ex.has_error())
                return ex.error();

            tx_max_buf = ex.value();
            return 0;
        }

        case SO_REUSEADDR: {
            auto ex = get_socket_option<int>(optval, optlen);

            if (ex.has_error())
                return ex.error();

            reuse_addr = ex.value();
            return 0;
        }

        case SO_BROADCAST: {
            auto ex = get_socket_option<int>(optval, optlen);

            if (ex.has_error())
                return ex.error();

            broadcast_allowed = ex.value() != 0;
            return 0;
        }
    }

    return -ENOPROTOOPT;
}

int sys_getsockopt(int sockfd, int level, int optname, void *optval, socklen_t *optlen)
{
    auto f = get_socket_fd(sockfd);
    if (!f)
        return -errno;

    socklen_t length;

    if (copy_from_user(&length, optlen, sizeof(length)) < 0)
        return -EFAULT;

    socklen_t original_length = length;

    void *ptr = malloc(length);
    if (!ptr)
        return -ENOMEM;

    socket *sock = file_to_socket(f);

    int st = sock->getsockopt(level, optname, ptr, &length);

    if (st < 0)
    {
        free(ptr);
        return st;
    }

    st = copy_to_user(optval, ptr, min(original_length, length));

    free(ptr);

    if (st < 0)
        return -EFAULT;

    if (copy_to_user(optlen, &length, sizeof(length)) < 0)
        return -EFAULT;

    return st;
}

int sys_setsockopt(int sockfd, int level, int optname, const void *uoptval, socklen_t optlen)
{
    auto f = get_socket_fd(sockfd);
    if (!f)
        return -errno;

    void *ptr = malloc(optlen);
    if (!ptr)
        return -ENOMEM;

    if (copy_from_user(ptr, uoptval, optlen) < 0)
        return -EFAULT;

    socket *sock = file_to_socket(f);

    int st = sock->setsockopt(level, optname, ptr, optlen);

    free(ptr);

    return st;
}

#define INLINE_IOVECS 4

struct msghdr_guard
{
    iovec *vecs;
    iovec inline_vecs[INLINE_IOVECS];
    sockaddr_storage sa;
    int vecs_allocated : 1;
    void *msg_control;
    void *ucontrol{};
    void *uiov{};
    void *uname{};

    msghdr_guard() : vecs{inline_vecs}, inline_vecs{}, sa{}, vecs_allocated{0}, msg_control{}
    {
    }

    ~msghdr_guard()
    {
        if (vecs_allocated)
            delete[] vecs;

        free(msg_control);
    }
};

int copy_msghdr_from_user(msghdr *msg, const msghdr *umsg, msghdr_guard &guard)
{
    if (copy_from_user(msg, umsg, sizeof(msghdr)) < 0)
        return -EFAULT;

    if (msg->msg_name)
    {
        if (msg->msg_namelen > sizeof(sockaddr_storage))
            return -EINVAL;

        if (copy_from_user(&guard.sa, msg->msg_name, msg->msg_namelen) < 0)
            return -EFAULT;

        guard.uname = msg->msg_name;

        msg->msg_name = &guard.sa;
    }

    if (msg->msg_iovlen < 0)
        return -EINVAL;

    if (msg->msg_iovlen > INLINE_IOVECS)
    {
        if (msg->msg_iovlen > IOV_MAX)
            return -EINVAL;

        guard.vecs = new iovec[msg->msg_iovlen];
        if (!guard.vecs)
            return -ENOMEM;
        guard.vecs_allocated = 1;
    }

    if (copy_from_user(guard.vecs, msg->msg_iov, sizeof(iovec) * msg->msg_iovlen) < 0)
        return -EFAULT;

    guard.uiov = msg->msg_iov;

    msg->msg_iov = guard.vecs;

    if (msg->msg_control)
    {
        auto buf = malloc(msg->msg_controllen);
        if (!buf)
            return -ENOMEM;

        if (copy_from_user(buf, msg->msg_control, msg->msg_controllen) < 0)
            return -EFAULT;

        guard.ucontrol = msg->msg_control;
        guard.msg_control = msg->msg_control = buf;
    }

    return 0;
}

ssize_t socket_sendmsg(socket *sock, msghdr *umsg, int flags)
{
    msghdr msg;
    msghdr_guard g;

    if (int st = copy_msghdr_from_user(&msg, umsg, g); st < 0)
        return st;

    return sock->sendmsg(&msg, flags);
}

ssize_t sys_sendto(int sockfd, const void *buf, size_t len, int flags, struct sockaddr *addr,
                   socklen_t addrlen)
{
    auto desc = get_socket_fd(sockfd);
    if (!desc)
        return -errno;

    /* Ugh, this uses a big part of the stack... I don't like this
     * and we're going to get rid of this anyway when we add sendmsg
     */
    sockaddr_storage sa;

    if (addr)
    {
        if (addrlen > sizeof(sa))
            return -EINVAL;

        if (copy_from_user(&sa, addr, addrlen) < 0)
            return -EFAULT;
    }

    msghdr msg;
    msg.msg_control = nullptr;
    msg.msg_controllen = 0;
    msg.msg_flags = 0;

    iovec vec0;
    /* This cast is safe because sendmsg won't write to the iov */
    vec0.iov_base = const_cast<void *>(buf);
    vec0.iov_len = len;
    msg.msg_iov = &vec0;
    msg.msg_iovlen = 1;
    msg.msg_name = addr ? &sa : nullptr;
    msg.msg_namelen = addr ? addrlen : 0;

    socket *s = file_to_socket(desc);
    ssize_t ret = s->sendmsg(&msg, flags);

    return ret;
}

ssize_t sys_sendmsg(int sockfd, struct msghdr *msg, int flags)
{
    auto_file f = get_socket_fd(sockfd);
    if (!f)
        return -errno;

    socket *sock = file_to_socket(f);

    return socket_sendmsg(sock, msg, flags | fd_flags_to_msg_flags(f.get_file()));
}

ssize_t socket_recvmsg(socket *sock, msghdr *umsg, int flags)
{
    msghdr msg;
    msghdr_guard g;

    if (int st = copy_msghdr_from_user(&msg, umsg, g); st < 0)
        return st;

    auto st = sock->recvmsg(&msg, flags);

    if (st < 0)
        return st;

    msg.msg_control = g.ucontrol;
    msg.msg_iov = (iovec *) g.uiov;
    msg.msg_name = g.uname;

    if (msg.msg_control)
    {
        if (copy_to_user(msg.msg_control, g.msg_control, msg.msg_controllen) < 0)
            return -EFAULT;
    }

    if (msg.msg_name)
    {
        if (copy_to_user(msg.msg_name, g.uname, msg.msg_namelen) < 0)
            return -EFAULT;
    }

    if (copy_to_user(umsg, &msg, sizeof(msghdr)) < 0)
        return -EFAULT;

    return st;
}

ssize_t sys_recvmsg(int sockfd, struct msghdr *msg, int flags)
{
    auto_file f = get_socket_fd(sockfd);
    if (!f)
        return -errno;

    socket *sock = file_to_socket(f);

    return socket_recvmsg(sock, msg, flags | fd_flags_to_msg_flags(f.get_file()));
}

void sock_do_post_work(socket *sock)
{
    return sock->handle_backlog();
}

bool sock_needs_work(socket *sock)
{
    return !list_is_empty(&sock->socket_backlog);
}

/**
 * @brief Copies a sockaddr over to userspace using the regular BSD socket semantics.
 *
 * @param kaddr Pointer to kernel-space sockaddr
 * @param kaddrlen Length of the sockaddr we want to copy
 * @param uaddr Pointer to user-space sockaddr buffer
 * @param uaddrlen Pointer to length of uspace buffer (In the end of the call, it has the actual
 * size (kaddrlen))
 * @return 0 on success, negative error codes
 */
int copy_sockaddr(const sockaddr *kaddr, socklen_t kaddrlen, sockaddr *uaddr, socklen_t *uaddrlen)
{
    socklen_t user_len;

    if (copy_from_user(&user_len, uaddrlen, sizeof(socklen_t)) < 0)
        return -EFAULT;

    // See if we need to truncate the address

    const auto final_size = min(user_len, kaddrlen);

    if (copy_to_user(uaddr, kaddr, final_size) < 0)
        return -EFAULT;

    if (copy_to_user(uaddrlen, &user_len, sizeof(socklen_t)) < 0)
        return -EFAULT;

    return 0;
}

int sys_getsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
    sockaddr_storage kaddr;
    socklen_t kaddrlen;
    auto_file f = get_socket_fd(sockfd);
    if (!f)
        return -errno;

    socket *sock = file_to_socket(f);

    int st = sock->getsockname((sockaddr *) &kaddr, &kaddrlen);

    if (st < 0)
        return st;

    return copy_sockaddr((sockaddr *) &kaddr, kaddrlen, addr, addrlen);
}

int sys_getpeername(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
    sockaddr_storage kaddr;
    socklen_t kaddrlen;
    auto_file f = get_socket_fd(sockfd);
    if (!f)
        return -errno;

    socket *sock = file_to_socket(f);

    if (!sock->connected)
        return -ENOTCONN;

    int st = sock->getpeername((sockaddr *) &kaddr, &kaddrlen);

    if (st < 0)
        return st;

    return copy_sockaddr((sockaddr *) &kaddr, kaddrlen, addr, addrlen);
}
