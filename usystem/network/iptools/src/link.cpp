/*
 * Copyright (c) 2021 - 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#include <net/if.h>
#include <net/if_arp.h>
#include <object.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstring>
#include <utility>

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
    (void) argv;
    (void) argc;
    std::printf("Usage: \tip link help\n\n"
                " \tip link show [DEVICE] [up]\n");
    return 0;
}

std::pair<short, std::string> if_flag_symbols[] = {
    {IFF_UP, "UP"},
    {IFF_BROADCAST, "BROADCAST"},
    {IFF_DEBUG, "DEBUG"},
    {IFF_LOOPBACK, "LOOPBACK"},
    {IFF_POINTOPOINT, "POINTOPOINT"},
    {IFF_NOTRAILERS, "NOTRAILERS"},
    {IFF_RUNNING, "RUNNING"},
    {IFF_NOARP, "NOARP"},
    {IFF_PROMISC, "PROMISC"},
    {IFF_ALLMULTI, "ALLMULTI"},
    {IFF_MASTER, "MASTER"},
    {IFF_SLAVE, "SLAVE"},
};

void print_mac_address(sockaddr &sa)
{
    std::printf("%02x:%02x:%02x:%02x:%02x:%02x", (unsigned char) sa.sa_data[0],
                (unsigned char) sa.sa_data[1], (unsigned char) sa.sa_data[2],
                (unsigned char) sa.sa_data[3], (unsigned char) sa.sa_data[4],
                (unsigned char) sa.sa_data[5]);
}

int link_show(const char **argv, int argc)
{
    std::string wanted_device;
    bool only_up = false;

    for (int i = 0; i < argc; i++)
    {
        if (!strcmp(argv[i], "up"))
            only_up = true;
        else
        {
            if (!wanted_device.empty())
            {
                std::fprintf(stderr, "Error: either \"dev\" is duplicate, or \"%s\" is garbage\n",
                             argv[i]);
                return 1;
            }

            wanted_device = argv[i];
        }
    }

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

    if (sendto(fd.get(), (const void *) &msg, sizeof(msg), 0, (const sockaddr *) &addr,
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
        netkernel_nif_interface nif;
        if (recv(fd.get(), &nif, sizeof(nif), 0) < 0)
        {
            std::perror("netkernel error");
            return 1;
        }

        if (only_up && !(nif.if_flags & IFF_UP))
            continue;

        if (!wanted_device.empty() && std::string(nif.if_name) != wanted_device)
            continue;

        std::string flags = "<";

        for (auto &f : if_flag_symbols)
        {
            if (nif.if_flags & f.first)
            {
                if (flags.length() != 1)
                    flags += ", ";
                flags += f.second;
                nif.if_flags &= ~f.first;
            }
        }

        if (nif.if_flags != 0)
        {
            // Support unknown flags by simply blitting them
            if (flags.length() != 1)
                flags += ", ";
            char buf[20];
            std::snprintf(buf, 20, "0x%x", nif.if_flags);
            flags += std::string(buf);
        }

        flags += ">";

        std::printf("%u: %s %s mtu %u\n", nif.if_index, nif.if_name, flags.c_str(), nif.if_mtu);
        std::string linktype;

        switch (nif.if_hwaddr.sa_family)
        {
            case ARPHRD_ETHER: {
                linktype = "ether";
                break;
            }
            case ARPHRD_LOOPBACK: {
                linktype = "loopback";
                break;
            }
            default: {
                char buf[40];
                std::snprintf(buf, 40, "0x%x", nif.if_hwaddr.sa_family);
                linktype = std::string(buf);
            }
        }

        std::printf("    link/%s ", linktype.c_str());

        // Now print the address and broadcast addr
        // Note: We're only printing 6-len addresses a-la MAC
        print_mac_address(nif.if_hwaddr);
        std::printf(" brd ");
        print_mac_address(nif.if_brdaddr);
        std::printf("\n");
    }

    return 0;
}

} // namespace link

} // namespace iptools

object *link_obj = &iptools::link::link_obj_;
