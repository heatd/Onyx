/*
 * Copyright (c) 2020 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 */
#pragma once

#include <dhcp.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <array>
#include <functional>
#include <list>
#include <stdexcept>
#include <string>
#include <thread>

#include <onyx/slice.hpp>

namespace dhcpcd
{

extern int rtfd;

void init_entropy(void);
int create_instance(std::string& name);

struct dhcp_option
{
    uint8_t length;
    uint8_t type;
    cul::slice<unsigned char> option;

    dhcp_option(unsigned char* ptr, uint8_t type, uint8_t length)
        : length(length), type(type), option{ptr, length}
    {
    }
};

struct packet
{
    dhcp_packet_t* packet_;
    size_t length;
    struct sockaddr src;
    socklen_t len;
    std::list<dhcp_option> options;

    bool decode();

    ~packet()
    {
        delete packet_;
    }

    dhcp_option* get_option(uint8_t type, uint8_t length)
    {
        for (auto& o : options)
        {
            if (o.type == type && o.length >= length)
                return &o;
        }

        return nullptr;
    }
};

class instance
{
private:
    std::string device_name;
    int fd;
    std::thread thread;
    int sockfd;
    std::array<unsigned char, 6> mac;
    dhcp_packet_t* buf;
    bool got_dhcp_offer;
    uint32_t xid;

    void run();
    int setup_netif();
    void send_discover();
    std::unique_ptr<packet> get_packets(std::function<bool(packet*)> pred);
    void send_request(uint32_t ip, uint32_t selected_server);

public:
    instance(int fd, std::string& name)
        : fd(fd), device_name(name), thread{}, sockfd{-1}, mac{}, buf{new dhcp_packet_t},
          got_dhcp_offer{false}, xid((uint32_t) random())
    {
        if (ioctl(fd, SIOGETMAC, mac.data()) < 0)
        {
            throw std::runtime_error(std::string("ioctl: Could not get the local mac address: ") +
                                     strerror(errno));
        }

        thread = std::thread{&instance::run, this};
    }

    ~instance()
    {
        thread.join();
        close(fd);
    }

    instance(instance&& other)
    {
        device_name = std::move(other.device_name);
        fd = std::move(other.fd);
        thread = std::move(other.thread);
        sockfd = std::move(other.sockfd);
    }
};

} // namespace dhcpcd
