/*
 * Copyright (c) 2020 - 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#include <onyx/init.h>
#include <onyx/net/netkernel.h>

#include <onyx/string_view.hpp>

namespace netkernel
{

struct path_parsing_data
{
    std::string_view view;
    size_t pos;
    shared_ptr<netkernel_object> curr_obj;
};

/* Shamelessly stolen from me and adapted, original code at fs/dentry.cpp */

std::string_view get_token_from_path(path_parsing_data &data)
{
    const auto &view = data.view;
    while (true)
    {
        data.pos = view.find_first_not_of('.', data.pos);
        if (data.pos == std::string_view::npos)
            break;

        auto path_elem_end = view.find('.', data.pos);
        // std::cout << "end at pos " << path_elem_end << "\n";
        // std::cout << "pos: " << pos << "\n";
        if (path_elem_end == std::string_view::npos) [[unlikely]]
            path_elem_end = view.length();

        // std::cout << "Elem size: " << path_elem_end - pos << "\n";
        std::string_view v = view.substr(data.pos, path_elem_end - data.pos);
        data.pos += v.length() + 1;
        // std::cout << "Path element: " << v << "\n";

        return v;
    }

    return {};
}

shared_ptr<netkernel_object> root_object{};

shared_ptr<netkernel_object> open(std::string_view path)
{
    path_parsing_data pdata;
    pdata.view = path;
    pdata.pos = 0;
    pdata.curr_obj = root_object;

    std::string_view v;
    // printk("Path: %s\n", path.data());

    while ((v = get_token_from_path(pdata)).data() != nullptr)
    {
        // printk("%.*s\n", (int) v.length(), v.data());

        auto new_obj = pdata.curr_obj->find(v);

        if (!new_obj)
            return nullptr;
        // printk("found\n");
        pdata.curr_obj = new_obj;
    }

    return pdata.curr_obj;
}

int netkernel_socket::getsockopt(int level, int optname, void *optval, socklen_t *optlen)
{
    if (level == SOL_SOCKET)
        return getsockopt_socket_level(optname, optval, optlen);

    return -ENOPROTOOPT;
}

int netkernel_socket::setsockopt(int level, int optname, const void *optval, socklen_t optlen)
{
    if (level == SOL_SOCKET)
        return setsockopt_socket_level(optname, optval, optlen);

    return -ENOPROTOOPT;
}

static constexpr bool validate_sockaddr(const sockaddr *addr, socklen_t len)
{
    if (len != sizeof(sockaddr_nk)) [[unlikely]]
        return false;

    if (addr->sa_family != AF_NETKERNEL) [[unlikely]]
        return false;

    return true;
}

static expected<size_t, int> nk_look_at_sa_path(const sockaddr_nk *nk)
{
    size_t len = 0;
    for (const auto &c : nk->path)
    {
        if (c == '\0')
            return len;

        len++;
    }

    return unexpected<int>{-EINVAL};
}

int netkernel_socket::connect(sockaddr *addr, socklen_t addrlen, int flags)
{
    if (!validate_sockaddr(addr, addrlen))
        return -EINVAL;

    sockaddr_nk *nk = (sockaddr_nk *) addr;

    auto res = nk_look_at_sa_path(nk);
    if (res.has_error())
        return res.error();

    auto obj = open({nk->path, res.value()});

    if (!obj || obj->get_flags() & NETKERNEL_OBJECT_PATH_ELEMENT)
        return -ECONNREFUSED;

    dst = obj;
    connected = true;

    return 0;
}

#define NETKERNEL_HDR_VALID_FLAGS_MASK 0

ssize_t netkernel_socket::sendmsg(const struct msghdr *msg, int flags)
{
    auto addr = (const sockaddr *) msg->msg_name;
    auto addrlen = msg->msg_namelen;
    if (!addr && !connected)
        return -ENOTCONN;

    auto len = iovec_count_length(msg->msg_iov, msg->msg_iovlen);
    if (len < 0)
        return len;

    auto obj = dst;

    if (addr)
    {
        if (!validate_sockaddr(addr, addrlen))
            return -EINVAL;
        sockaddr_nk *nk = (sockaddr_nk *) addr;

        auto res = nk_look_at_sa_path(nk);
        if (res.has_error())
            return res.error();

        obj = open({nk->path, res.value()});

        if (!obj || obj->get_flags() & NETKERNEL_OBJECT_PATH_ELEMENT)
            return -ECONNREFUSED;
    }

    unsigned char *buf = new unsigned char[len];
    if (!buf)
        return -ENOMEM;
    auto bufp = buf;

    for (int i = 0; i < msg->msg_iovlen; i++)
    {
        const auto &vec = msg->msg_iov[i];

        if (copy_from_user(bufp, vec.iov_base, vec.iov_len) < 0)
            return -EFAULT;

        bufp += vec.iov_len;
    }

    auto hdr = (netkernel_hdr *) buf;

    if (hdr->flags & ~NETKERNEL_HDR_VALID_FLAGS_MASK || hdr->size > (size_t) len)
    {
        delete[] buf;
        return -EINVAL;
    }

    auto result = obj->serve_request((netkernel_hdr *) buf);

    if (result.has_error())
    {
        panic("nksend");
        return result.error();
    }

    auto result_buf = result.value();

    if (!result_buf)
    {
        // No answer
        return len;
    }

    packetbuf *pbuf = new packetbuf;

    if (!pbuf)
    {
        delete[] result_buf;
        return -ENOBUFS;
    }

    auto rx_len = result.value()->size;

    if (!pbuf->allocate_space(rx_len))
    {
        delete[] result_buf;
        delete pbuf;
        return -ENOBUFS;
    }

    void *ptr = pbuf->put(rx_len);
    memcpy(ptr, result.value(), rx_len);
    rx_pbuf(pbuf);

    delete[] result_buf;

    return len;
}

ssize_t netkernel_socket::recvmsg(struct msghdr *msg, int flags)
{
    auto iovlen = iovec_count_length(msg->msg_iov, msg->msg_iovlen);
    if (iovlen < 0)
        return iovlen;

    auto st = get_datagram(flags);
    if (st.has_error())
        return st.error();

    auto buf = st.value();
    ssize_t read = min(iovlen, (long) buf->length());
    ssize_t was_read = 0;
    ssize_t to_ret = read;

    if (iovlen < buf->length())
        msg->msg_flags = MSG_TRUNC;

    if (flags & MSG_TRUNC)
    {
        to_ret = buf->length();
    }

    const unsigned char *ptr = buf->data;

    if (msg->msg_name)
    {
        // TODO
    }

    for (int i = 0; i < msg->msg_iovlen; i++)
    {
        auto iov = msg->msg_iov[i];
        auto to_copy = min((ssize_t) iov.iov_len, read - was_read);
        if (copy_to_user(iov.iov_base, ptr, to_copy) < 0)
        {
            spin_unlock(&rx_packet_list_lock);
            return -EFAULT;
        }

        was_read += to_copy;

        ptr += to_copy;

        buf->data += to_copy;
    }

    msg->msg_controllen = 0;

    if (!(flags & MSG_PEEK))
    {
        if (buf->length() == 0)
        {
            list_remove(&buf->list_node);
            buf->unref();
        }
    }

    spin_unlock(&rx_packet_list_lock);

    return to_ret;
}

socket *create_socket(int type)
{
    return new netkernel_socket{type};
}

void netkernel_init()
{
    root_object = make_shared<netkernel_object>("");
    assert(root_object != nullptr);

    root_object->set_flags(NETKERNEL_OBJECT_PATH_ELEMENT);
}

INIT_LEVEL_CORE_AFTER_SCHED_ENTRY(netkernel_init);

} // namespace netkernel
