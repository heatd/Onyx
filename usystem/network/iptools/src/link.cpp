/*
 * Copyright (c) 2021 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 */

#include <object.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstring>

#include <onyx/public/netkernel.h>

#include <libonyx/unique_fd.h>

namespace iptools
{

namespace link
{

int link_show(const char **argv, int argc);
int link_help(const char **argv, int argc);

static command commands[] = {{"show", link_show}, {"help", link_help}};

class link_object : public object
{
public:
    link_object() : object("link")
    {
    }

    std::span<command> get_commands() const override
    {
        return {commands, sizeof(commands) / sizeof(commands[0])};
    }
};

static link_object link_obj_;

int link_help(const char **argv, int argc)
{
    std::printf("Usage: \tip link help\n"
                " \tip link show\n");
    return 0;
}

int link_show(const char **argv, int argc)
{
    onx::unique_fd fd{socket(AF_NETKERNEL, SOCK_STREAM, 0)};
    if (fd.get() < 0)
    {
        std::perror("Error creating netkernel socket");
        return 1;
    }

    sockaddr_nk addr;
    addr.nk_family = AF_NETKERNEL;
    std::strcpy(addr.path, "netif.netif_table");

    netkernel_hdr msg;
    msg.msg_type = NETKERNEL_MSG_NETIF_GET_NETIFS;
    msg.flags = 0;
    msg.size = sizeof(netkernel_hdr);

    if (sendto(fd.get(), (const void *)&msg, sizeof(msg), 0, (const sockaddr *)&addr,
               sizeof(addr)) < 0)
    {
        std::perror("netkernel error");
        return 1;
    }

    netkernel_get_nifs_response resp;

    if (recv(fd.get(), &resp, sizeof(resp), 0) < 0)
    {
        std::perror("netkernel error");
        return 1;
    }

    if (resp.hdr.msg_type != NETKERNEL_MSG_NETIF_GET_NETIFS)
    {
        std::perror("netkernel error");
        return 1;
    }

    for (unsigned int i = 0; i < resp.nr_ifs; i++)
    {
        netkernel_get_nif_interface nif;
        if (recv(fd.get(), &nif, sizeof(nif), 0) < 0)
        {
            std::perror("netkernel error");
            return 1;
        }

        std::printf("Interface %s, index %u\n", nif.iface, nif.if_index);
    }

    return 0;
}

} // namespace link

} // namespace iptools

object *link_obj = &iptools::link::link_obj_;
