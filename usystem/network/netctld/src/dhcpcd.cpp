/*
 * Copyright (c) 2017 - 2024 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
#include <arpa/inet.h>
#include <assert.h>
#include <dhcp.h>
#include <dirent.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#include <cstring>
#include <memory>
#include <stdexcept>
#include <thread>
#include <vector>

#include <uapi/icmp.h>
#include <uapi/netkernel.h>

#include <dhcpcd.hpp>

#define DHCP_MIN_OPT_OFFSET 4

void error(const char *msg, ...)
{
    va_list ap;
    va_start(ap, msg);
    fprintf(stderr, "%s: error: ", program_invocation_short_name);
    vfprintf(stderr, msg, ap);
    va_end(ap);
}

void errorx(const char *msg, ...)
{
    va_list ap;
    va_start(ap, msg);
    fprintf(stderr, "%s: error: ", program_invocation_short_name);
    vfprintf(stderr, msg, ap);
    va_end(ap);
    exit(1);
}

namespace dhcpcd
{

int rtfd = -1;

void init_entropy(void)
{
    unsigned int seed = 0;
    if (syscall(SYS_getrandom, &seed, sizeof(seed), 0) < 0)
        errorx("Couldn't gather entropy: %s\n", strerror(errno));
    struct timespec t;
    if (clock_gettime(CLOCK_REALTIME, &t) < 0)
    {
        errorx("Could not read the current time: %s\n", strerror(errno));
    }

    srandom(seed ^ (t.tv_nsec ^ t.tv_sec));
}

off_t dhcp_add_option(dhcp_packet_t *pkt, off_t off, unsigned char len, const void *buf,
                      size_t size_buf, unsigned char opt)
{
    pkt->options[off++] = opt;
    pkt->options[off++] = len;
    memcpy(&pkt->options[off], buf, size_buf);
    return off + size_buf;
}

off_t dhcp_close_options(dhcp_packet_t *pkt, off_t off)
{
    /* Add the needed padding */
    // memset(&pkt->options[off], 0, 3);
    // off += 3;
    pkt->options[off] = DHO_END;

    return off + 1;
}

bool packet::decode()
{
    unsigned char *limit = (unsigned char *) packet_ + length;

    unsigned char *opt = (unsigned char *) &packet_->options;

    if (length <= DHCP_FIXED_NON_UDP)
    {
        fprintf(stderr, "dhcpcd: Bad packet length %zu, ignoring!\n", length);
        return false;
    }

    if (memcmp(opt, DHCP_OPTIONS_COOKIE, 4) == 1)
    {
        fprintf(stderr, "dhcpcd: Bad cookie, ignoring!\n");
        return false;
    }

    bool has_message_type = false;

    opt += 4;
    while (*opt != DHO_END)
    {
        /* Check for OOB */
        if (opt >= limit)
        {
            fprintf(stderr, "dhcpcd: Went out of bounds processing options, ignoring!\n");
            return false;
        }

        unsigned char type = *opt;
        opt++;
        unsigned char length = *opt;

        if (type == DHO_DHCP_MESSAGE_TYPE)
            has_message_type = true;

        dhcp_option option{opt + 1, type, length};

        options.push_back(std::move(option));

        opt = opt + length + 1;
    }

    if (!has_message_type)
    {
        fprintf(stderr, "dhcpcd: Does not have message type, ignoring!\n");
        return false;
    }

    return true;
}

void instance::send_discover()
{
    const char *vendor_class_identifier = "Onyx dhcpcd (netctld)";
    char hostname[512];
    uint16_t max_msg_size = htons(576);
    auto boot_packet = buf;
    memset(boot_packet, 0, sizeof(dhcp_packet_t));

    if (gethostname(hostname, sizeof(hostname) - 1) < 0)
        err(1, "gethostname");

    for (size_t i = 0; i < strlen(hostname); i++)
        hostname[i] = tolower(hostname[i]);

    hostname[sizeof(hostname) - 1] = 0;

    memcpy(&boot_packet->chaddr, &mac, 6);
    boot_packet->xid = xid;
    boot_packet->hlen = 6;
    boot_packet->htype = HTYPE_ETHER;
    boot_packet->op = BOOTREQUEST;
    boot_packet->flags = htons(BOOTP_BROADCAST);

    off_t off = DHCP_MIN_OPT_OFFSET;
    memcpy(&boot_packet->options, DHCP_OPTIONS_COOKIE, 4);

    unsigned char message_type = DHCPDISCOVER;
    off = dhcp_add_option(boot_packet, off, 1, &message_type, sizeof(message_type),
                          DHO_DHCP_MESSAGE_TYPE);
    unsigned char opts[] = {DHO_SUBNET_MASK, DHO_ROUTERS,     DHO_DOMAIN_NAME_SERVERS,
                            DHO_HOST_NAME,   DHO_DOMAIN_NAME, DHO_BROADCAST_ADDRESS,
                            DHO_NTP_SERVERS};
    off = dhcp_add_option(boot_packet, off, sizeof(opts), &opts, sizeof(opts),
                          DHO_DHCP_PARAMETER_REQUEST_LIST);
    off = dhcp_add_option(boot_packet, off, 2, &max_msg_size, 2, DHO_DHCP_MAX_MESSAGE_SIZE);
    off = dhcp_add_option(boot_packet, off, strlen(hostname), hostname, strlen(hostname),
                          DHO_HOST_NAME);
    off =
        dhcp_add_option(boot_packet, off, strlen(vendor_class_identifier), vendor_class_identifier,
                        strlen(vendor_class_identifier), DHO_VENDOR_CLASS_IDENTIFIER);
    off = dhcp_close_options(boot_packet, off);

    if (send(sockfd, boot_packet, DHCP_FIXED_NON_UDP + off, 0) < 0)
    {
        throw std::runtime_error(std::string("send: Error sending the boot packet: ") +
                                 strerror(errno));
    }
}

void instance::send_request(uint32_t ip, uint32_t selected_server)
{
    auto boot_packet = buf;
    memset(boot_packet, 0, sizeof(dhcp_packet_t));

    memcpy(&boot_packet->chaddr, &mac, 6);
    boot_packet->xid = xid;
    boot_packet->hlen = 6;
    boot_packet->htype = HTYPE_ETHER;
    boot_packet->op = BOOTREQUEST;
    boot_packet->flags = 0;

    off_t off = DHCP_MIN_OPT_OFFSET;
    memcpy(&boot_packet->options, DHCP_OPTIONS_COOKIE, 4);

    unsigned char message_type = DHCPREQUEST;
    off = dhcp_add_option(boot_packet, off, 1, &message_type, sizeof(message_type),
                          DHO_DHCP_MESSAGE_TYPE);
    off = dhcp_add_option(boot_packet, off, 4, &ip, 4, DHO_DHCP_REQUESTED_ADDRESS);
    off = dhcp_add_option(boot_packet, off, 4, &selected_server, 4, DHO_DHCP_SERVER_IDENTIFIER);

    unsigned char opts[3] = {DHO_SUBNET_MASK, DHO_ROUTERS, DHO_DOMAIN_NAME_SERVERS};
    off =
        dhcp_add_option(boot_packet, off, 3, &opts, sizeof(opts), DHO_DHCP_PARAMETER_REQUEST_LIST);
    off = dhcp_close_options(boot_packet, off);

    if (send(sockfd, boot_packet, DHCP_FIXED_NON_UDP + off, 0) < 0)
    {
        throw std::runtime_error(std::string("send: Error sending the boot packet: ") +
                                 strerror(errno));
    }
}

std::unique_ptr<packet> instance::get_packets(std::function<bool(packet *)> pred)
{
    std::unique_ptr<packet> p = std::make_unique<packet>();

    dhcp_packet_t *packet = new dhcp_packet_t();
    p->packet_ = packet;
    struct sockaddr addr;
    socklen_t addrlen = sizeof(addr);

    auto length = recvfrom(sockfd, packet, sizeof(dhcp_packet_t), 0, &addr, &addrlen);

    if (length < 0)
    {
        throw std::runtime_error(std::string("recv: Error recieving packet: ") + strerror(errno));
    }

    p->src = addr;
    p->len = addrlen;
    p->length = length;

    if (!p->decode())
    {
        /* Note that the packet struct took ownership of the packet buffer */
        return nullptr;
    }

    /* Probably not for us */
    if (p->packet_->xid != xid)
        return nullptr;

    auto message_type = p->get_option(DHO_DHCP_MESSAGE_TYPE, 1);

    assert(message_type != nullptr);

    auto pdata = message_type->option.data();

    printf("dhcpcd: Got message type %x\n", *pdata);
    if (*pdata == DHCPOFFER)
    {
        if (got_dhcp_offer)
            return nullptr;
        else
            got_dhcp_offer = true;
    }

    /* If it's not the packet we want, delete it */
    if (!pred(p.get()))
    {
        return nullptr;
    }

    return p;
}

static bool check_for_dhcpoffer(dhcpcd::packet *data)
{
    auto message_type = data->get_option(DHO_DHCP_MESSAGE_TYPE, 1);
    assert(message_type != nullptr);

    auto pdata = message_type->option.data();

    if (*pdata != DHCPOFFER)
    {
        fprintf(stderr, "dhcpcd: Expecting DHCPOFFER, got %x, ignoring\n", *pdata);
        return false;
    }

    if (!data->get_option(DHO_ROUTERS, 4))
    {
        fprintf(stderr, "dhcpcd: DHCPOFFER does not supply DHO_ROUTERS, ignoring\n");
        return false;
    }

    return true;
}

int instance::setup_netif()
{
    /* DHCP essentially works like this:
     * 1) The client sends a DHCP discover request through broadcast
     * 2) The various DHCP servers on the local network reply
     * 3) The client picks one and sends a DHCPREQUEST through broadcast, requesting the picked IP
     * address. It's sent through broadcast as to signal the other DHCP servers that we didn't pick
     * their address. We get send a DHCP ACK packet, containing a NACK or ACK.
     */

    send_discover();

    std::unique_ptr<packet> packet;

    /* If for some reason we can't retrieve a packet, the get_packets will throw an exception */
    while (!(packet = get_packets(check_for_dhcpoffer)))
    {
    }

    uint32_t router_ip = 0;
    uint32_t subnet_mask = 0;
    in_addr_t dns_server;
    uint32_t lease_time = 0;

    uint32_t our_ip = packet->packet_->yiaddr;

    dhcp_option *opt = packet->get_option(DHO_DOMAIN_NAME_SERVERS, 4);

    if (opt != nullptr)
    {
        std::memcpy(&dns_server, opt->option.data(), sizeof(dns_server));
    }

    opt = packet->get_option(DHO_ROUTERS, 4);

    if (opt != nullptr)
    {
        std::memcpy(&router_ip, opt->option.data(), sizeof(router_ip));
    }

    opt = packet->get_option(DHO_SUBNET_MASK, 4);

    if (opt != nullptr)
    {
        std::memcpy(&subnet_mask, opt->option.data(), sizeof(subnet_mask));
    }

    opt = packet->get_option(DHO_DHCP_LEASE_TIME, 4);

    if (opt != nullptr)
    {
        std::memcpy(&lease_time, opt->option.data(), sizeof(lease_time));
        lease_time = ntohl(lease_time);
    }

    memset(buf, 0, sizeof(dhcp_packet_t));

    struct sockaddr_in *inaddr = (struct sockaddr_in *) &packet->src;
    send_request(our_ip, inaddr->sin_addr.s_addr);

    while (!(packet = get_packets([](dhcpcd::packet *data) -> bool {
                 auto message_type = data->get_option(DHO_DHCP_MESSAGE_TYPE, 1);

                 assert(message_type != nullptr);

                 auto pdata = message_type->option.data();
                 return *pdata == DHCPACK || *pdata == DHCPNAK;
             })))
    {
    }

    auto message_type = packet->get_option(DHO_DHCP_MESSAGE_TYPE, 1);

    auto pdata = message_type->option.data();

    /* TODO: What should we do on DHCP nack? */
    if (*pdata != DHCPACK)
        return -1;

    struct if_config_inet cfg;
    cfg.address.s_addr = our_ip;
    cfg.subnet.s_addr = subnet_mask;
    cfg.router.s_addr = router_ip;
    if (ioctl(fd, SIOSETINET4, &cfg) < 0)
    {
        perror("SIOSETINET4");
        return -1;
    }

    struct netkernel_route4_add msg;
    msg.hdr.msg_type = NETKERNEL_MSG_ROUTE4_ADD;
    msg.hdr.flags = 0;
    msg.hdr.size = sizeof(msg);
    msg.dest.s_addr = 0;
    msg.gateway.s_addr = router_ip;
    msg.mask.s_addr = 0;
    msg.metric = 100;
    msg.flags = ROUTE4_FLAG_GATEWAY;
    strcpy(msg.iface, device_name.c_str() + 5);

    if (send(rtfd, &msg, sizeof(msg), 0) < 0)
        perror("nksend");

    msg.dest.s_addr = our_ip & subnet_mask;
    msg.gateway.s_addr = 0;
    msg.mask.s_addr = subnet_mask;
    msg.flags = 0;

    if (send(rtfd, &msg, sizeof(msg), 0) < 0)
        perror("nksend");

    return 0;
}

void instance::run()
{
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0)
    {
        throw std::runtime_error(std::string("socket: ") + strerror(errno));
    }

    int bcast_allowed = 1;

    if (setsockopt(sockfd, SOL_SOCKET, SO_BROADCAST, &bcast_allowed, sizeof(bcast_allowed)) < 0)
    {
        throw std::runtime_error(std::string("setsockopt: ") + strerror(errno));
    }

    struct sockaddr_in sockaddr;
    sockaddr.sin_family = AF_INET;
    sockaddr.sin_port = htons(68);
    sockaddr.sin_addr.s_addr = INADDR_ANY;

    if (bind(sockfd, (const struct sockaddr *) &sockaddr, sizeof(struct sockaddr)) < 0)
    {
        throw std::runtime_error(std::string("bind: ") + strerror(errno));
    }

    sockaddr.sin_port = htons(67);
    sockaddr.sin_addr.s_addr = htonl(INADDR_BROADCAST);

    if (connect(sockfd, (const struct sockaddr *) &sockaddr, sizeof(struct sockaddr)) < 0)
    {
        throw std::runtime_error(std::string("connect: ") + strerror(errno));
    }

    setup_netif();
}

std::vector<std::unique_ptr<instance>> instances;

int create_instance(std::string &name)
{
    int fd = open(name.c_str(), O_RDWR);
    if (fd < 0)
    {
        auto error = strerror(errno);

        throw std::runtime_error("Failed to open " + name + ": " + error);
    }

    auto inst = std::make_unique<instance>(fd, name);

    instances.push_back(std::move(inst));

    return 0;
}

} // namespace dhcpcd
