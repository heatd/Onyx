/*
 * Copyright (c) 2020 - 2026 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <arpa/inet.h>
#include <netinet/icmp6.h>
#include <poll.h>
#include <sys/socket.h>

#include <cassert>
#include <chrono>
#include <iostream>
#include <random>
#include <span>
#include <utility>
#include <vector>

#include <uapi/icmp.h>
#include <uapi/netkernel.h>

#include <netctl.hpp>
#include <v6/addrcfg.hpp>
#include <v6/mldv2.hpp>

#define ICMPV6_ROUTER_SOLICIT    133
#define ICMPV6_ROUTER_ADVERT     134
#define ICMPV6_NEIGHBOUR_SOLICIT 135
#define ICMPV6_NEIGHBOUR_ADVERT  136

namespace netctl
{

namespace v6
{

using namespace std::chrono;

static constexpr unsigned int DupAddrDetectTransmits = 1;
static constexpr auto RetransTimerMs = 1000ms;
/* rfc4861 constants */
static constexpr auto MAX_RTR_SOLICITATIONS = 3;
static constexpr auto RTR_SOLICITATION_INTERVAL = 4s;
static constexpr auto MAX_RTR_SOLICITATION_DELAY = 1000ms;

void configure_address_mac(netctl::instance &inst, in6_addr &addr)
{
    /* Let's get our EUI-64 IID */
    auto mac = inst.get_mac();

    /* First, set the prefix to the local prefix */
    addr.s6_addr[0] = 0xfe;
    addr.s6_addr[1] = 0x80;

    /* Then the address is formed by bytes[0...3] = mac[0...3] */
    for (int i = 0; i < 3; i++)
        addr.s6_addr[8 + i] = mac[i];

    /* We then insert 0xff, 0xfe in the middle of the mac address */
    addr.s6_addr[11] = 0xff;
    addr.s6_addr[12] = 0xfe;

    /*  Insert mac[3...6] in bytes[5...7] */
    for (int i = 0; i < 3; i++)
        addr.s6_addr[13 + i] = mac[i + 3];

    /* Then, we flip MSB bit 7 of the mac address */
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    addr.s6_addr[8] ^= (1 << 7);
#else
    addr.s6_addr[8] ^= (1 << 1);
#endif
}

void configure_address_random(netctl::instance &instance, in6_addr &addr)
{
    (void) instance;
    std::random_device dev;
    std::mt19937 rng(dev());
    std::uniform_int_distribution<std::mt19937::result_type> dist(0, 255);

    addr.s6_addr[0] = 0xfe;
    addr.s6_addr[1] = 0x80;

    for (int i = 0; i < 7; i++)
        addr.s6_addr[8 + i] = dist(rng);
}

const in6_addr all_mldv2_capable_routers = {
    {{0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x16}}};
const in6_addr solicited_node_prefix = {{{0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0xff, 0x00}}};
const in6_addr all_nodes = {{{0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}}};
const in6_addr all_routers = {{{0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}}};

in6_addr solicited_node_address(const in6_addr &our_address)
{
    /* Per rfc4291, the solicited node address is formed by taking the low 24-bits of an address and
     * appending them to the solicited_node_prefix(see above).
     */
    auto ret = solicited_node_prefix;
    for (int i = 0; i < 3; i++)
        ret.s6_addr[13 + i] = our_address.s6_addr[13 + i];

    return ret;
}

void join_multicast(const in6_addr &addr, int sockfd, std::uint32_t scope_id)
{
    auto report_size = mldv2_report_size(1, 0);
    mldv2_report *report = (mldv2_report *) new uint8_t[report_size];

    memset(report, 0, report_size);

    report->header.icmp6_type = MLDV2_REPORT_MSG;
    report->header.icmp6_dataun.icmp6_un_data16[1] = htons(1);

    auto &record = report->records[0];
    record.aux_data_len = 0;
    record.mcast_address = addr;
    record.type = MCAST_CHANGE_TO_EXCLUDE;

    struct sockaddr_in6 all_capable = {};
    all_capable.sin6_addr = all_mldv2_capable_routers;
    all_capable.sin6_family = AF_INET6;
    all_capable.sin6_scope_id = scope_id;

    if (sendto(sockfd, report, report_size, 0, (const sockaddr *) &all_capable,
               sizeof(all_capable)) < 0)
    {
        throw sys_error("Error sending MLDv2 report");
    }
}

static_assert(sizeof(struct nd_neighbor_advert) == sizeof(struct nd_neighbor_solicit),
              "Both neighbour discovery message types need to be similarly sized");

ssize_t wait_for_neighbour_advert(const in6_addr &addr, int sockfd)
{
    socklen_t addr_len = sizeof(struct sockaddr_in6);
    struct nd_neighbor_advert na;
    struct sockaddr_in6 in;
    bool matches_addr;
    struct pollfd fd;
    ssize_t ret;

    fd.fd = sockfd;
    fd.events = POLLIN;
    fd.revents = 0;

    int st = poll(&fd, 1, 100);

    if (st == 0)
        return 0;

    ret = recvfrom(sockfd, &na, sizeof(na), 0, (struct sockaddr *) &in, &addr_len);
    if (ret < 0)
        throw sys_error("Error receiving packet");

    assert(addr_len == sizeof(struct sockaddr_in6));
    /* Weirdly-sized ICMPv6 packet, ignore */
    if ((size_t) ret != sizeof(na))
        return 1;

    /* Note that for RFC4862 purposes, @addr is tentative (aka not really ours yet). */
    matches_addr = !memcmp(&na.nd_na_target, &addr, sizeof(in6_addr));
    switch (na.nd_na_type)
    {
        case ICMPV6_NEIGHBOUR_ADVERT:
            /* rfc4862 5.4.4: If the target address is tentative, the tentative address is not
             * unique.*/
            if (matches_addr)
                return -1;
            break;
        case ICMPV6_NEIGHBOUR_SOLICIT:
            /* rfc4862 5.4.3: if source address is the unspecified address, against the tentative
             * address, it's someone doing DAD. In which case, it's an error. If it's a unicast
             * address, then it is someone doing regular neighbour discovery. This is fine. */
            if (IN6_IS_ADDR_UNSPECIFIED(&in.sin6_addr) && matches_addr)
                return -1;
    }
    return 1;
}

int perform_dad(const in6_addr &addr, int sockfd, std::uint32_t scope_id)
{
    struct sockaddr_in6 solicited_nodes = {};
    solicited_nodes.sin6_addr = solicited_node_address(addr);
    solicited_nodes.sin6_family = AF_INET6;
    solicited_nodes.sin6_scope_id = scope_id;
    unsigned int i = DupAddrDetectTransmits;

    while (i--)
    {
        struct nd_neighbor_solicit sol;
        memset(&sol, 0, sizeof(sol));
        sol.nd_ns_hdr.icmp6_type = ICMPV6_NEIGHBOUR_SOLICIT;
        sol.nd_ns_target = addr;

        if (sendto(sockfd, &sol, sizeof(sol), 0, (const sockaddr *) &solicited_nodes,
                   sizeof(solicited_nodes)) < 0)
            throw sys_error("Error sending neighbour discovery");

        ssize_t st = 0;

        while ((st = wait_for_neighbour_advert(addr, sockfd)) > 0)
            ;

        if (st == -1)
            return st;

        if (i != 0)
        {
            std::this_thread::sleep_for(RetransTimerMs);
        }
    }

    // std::cout << "DaD was successful\n";

    return 0;
}

struct icmp6_opt_header
{
    std::uint8_t type;

    /* In units of 8-octets */
    std::uint8_t length;
};

struct icmp6_source_link_layer_opt
{
    icmp6_opt_header hdr;
    unsigned char hwaddr[];
};

struct ipv6_prefix_info
{
    const in6_addr prefix;
    std::uint8_t prefix_len;
    std::uint8_t flags;
    std::uint32_t preferred_time, valid_time;
};

void parse_rt_advertisement(const nd_router_advert *adv, size_t len,
                            std::vector<ipv6_prefix_info> &prefixes)
{
    if (sizeof(*adv) > len)
        throw std::runtime_error("Invalid router advertisement length " + std::to_string(len));

    const auto flags = adv->nd_ra_flags_reserved;

    if (flags & ND_RA_FLAG_MANAGED)
    {
        /* TODO: We might want to use DHCPv6 in this case */
        throw std::runtime_error("Oh no, this router is managed only!");
    }

    const char *optptr = (const char *) (adv + 1);
    ssize_t options_len = len - sizeof(nd_router_advert);

    /* Each option is at least 8 bytes long */
    while (options_len >= 8)
    {
        auto hdr = (const icmp6_opt_header *) optptr;
        auto length = hdr->length << 3;
        if (length > options_len)
        {
            throw std::runtime_error("Invalid router advertisement: length " +
                                     std::to_string(length) + " > " + std::to_string(options_len));
        }

        switch (hdr->type)
        {
            case ND_OPT_PREFIX_INFORMATION: {
                auto info = (const nd_opt_prefix_info *) hdr;
                if (length != sizeof(nd_opt_prefix_info))
                {
                    throw std::runtime_error("Invalid option length");
                }

                ipv6_prefix_info info_{info->nd_opt_pi_prefix, info->nd_opt_pi_prefix_len,
                                       info->nd_opt_pi_flags_reserved,
                                       info->nd_opt_pi_preferred_time, info->nd_opt_pi_valid_time};

                prefixes.push_back(std::move(info_));
            }
        }

        optptr += length;
        options_len -= length;
    }
}

static nd_router_advert *send_rs(const in6_addr &addr, int sockfd, instance &inst,
                                 std::span<std::byte> buffer, size_t *plen,
                                 struct sockaddr_in6 *router_addr)
{
    constexpr size_t source_link_layer_opt = sizeof(icmp6_source_link_layer_opt) + 6;
    alignas(nd_router_solicit) char buf[sizeof(nd_router_solicit) + source_link_layer_opt];
    nd_router_solicit *sol = new (buf) nd_router_solicit;
    sol->nd_rs_hdr.icmp6_type = ICMPV6_ROUTER_SOLICIT;
    sol->nd_rs_hdr.icmp6_code = 0;
    sol->nd_rs_hdr.icmp6_dataun.icmp6_un_data32[0] = 0;

    auto *opt = new (&buf[sizeof(nd_router_solicit)]) icmp6_source_link_layer_opt;
    opt->hdr.type = ND_OPT_SOURCE_LINKADDR;
    opt->hdr.length = 1;

    const auto &mac = inst.get_mac();
    memcpy(&opt->hwaddr, mac.data(), mac.size());

    struct sockaddr_in6 all_rtrs = {};
    all_rtrs.sin6_addr = all_routers;
    all_rtrs.sin6_family = AF_INET6;
    all_rtrs.sin6_scope_id = inst.get_if_index();

    if (sendto(sockfd, buf, sizeof(buf), 0, (const sockaddr *) &all_rtrs, sizeof(all_rtrs)) < 0)
        throw sys_error("Error sending router solicit");

    nd_router_advert *adv = nullptr;
    ssize_t len = 0;

    socklen_t ra_len = sizeof(struct sockaddr_in6);
    auto deadline =
        std::chrono::steady_clock::now() +
        std::chrono::duration_cast<std::chrono::milliseconds>(RTR_SOLICITATION_INTERVAL);
    while (true)
    {
        /* Wait for a router advertisement */
        struct pollfd fd;
        fd.fd = sockfd;
        fd.events = POLLIN;
        fd.revents = 0;

        std::chrono::milliseconds timeout = std::chrono::duration_cast<std::chrono::milliseconds>(
            deadline - std::chrono::steady_clock::now());
        if (timeout.count() < 0)
            timeout = 0ms;
        int st = poll(&fd, 1, timeout.count());
        if (st == 0)
            break;

        len = recvfrom(sockfd, buffer.data(), buffer.size(), 0, (sockaddr *) router_addr, &ra_len);
        if (len < 0)
            throw sys_error("Error receiving packet");

        if ((size_t) len < sizeof(nd_router_advert))
            continue;

        adv = (nd_router_advert *) buffer.data();
        /* rfc4861 6.1.2: Validation of Router Advertisement Messages */
        /* TODO: we cannot get HOPLIMIT yet from recvfrom/recvmsg */
        if (adv->nd_ra_hdr.icmp6_type != ICMPV6_ROUTER_ADVERT || adv->nd_ra_code != 0)
            continue;
        if (!IN6_IS_ADDR_LINKLOCAL(&router_addr->sin6_addr))
            continue;
        *plen = len;
        return adv;
    }

    return nullptr;
}

void solicit_router(const in6_addr &addr, int sockfd, instance &inst)
{
    struct sockaddr_in6 router_addr;
    nd_router_advert *adv = nullptr;
    alignas(nd_router_advert) std::byte buffer[200];
    size_t ra_len;

    /* rfc4861 6.3.7: Before a host sends an initial solicitation, it SHOULD delay the transmission
     * for a random amount of time between 0 and MAX_RTR_SOLICITATION_DELAY. */
    std::this_thread::sleep_for(
        std::chrono::milliseconds{rand() % MAX_RTR_SOLICITATION_DELAY.count()});

    for (int i = 0; i < MAX_RTR_SOLICITATIONS; i++)
    {
        adv = send_rs(addr, sockfd, inst, std::span{buffer}, &ra_len, &router_addr);
        if (adv)
            break;
    }

    if (!adv)
        throw std::runtime_error("Could not get a router advertisement");

    std::vector<ipv6_prefix_info> prefixes;

    /* TODO: Manage lifetimes(same problem in dhcp code) */

    parse_rt_advertisement(adv, ra_len, prefixes);

    if (prefixes.size() == 0)
        throw std::runtime_error("Router advertisement contained no prefixes");

    for (auto &p : prefixes)
    {
        in6_addr a = {};
        memcpy(&a, &p.prefix, p.prefix_len / 8);
        memcpy(&a.s6_addr[8], &addr.s6_addr[8], 8);

        if (perform_dad(a, sockfd, inst.get_if_index()) < 0)
        {
            throw std::runtime_error("duplicated address");
        }

        if_inet6_addr arg;
        arg.address = a;
        arg.flags = INET6_ADDR_GLOBAL;
        arg.prefix_len = p.prefix_len;

        if (ioctl(inst.get_fd(), SIOADDINET6ADDR, &arg) < 0)
        {
            throw sys_error("SIOSETINET6");
        }
    }

    netkernel_route6_add route;
    route.dest = {};
    route.mask = {};
    route.gateway = router_addr.sin6_addr;
    route.hdr.flags = 0;
    route.hdr.msg_type = NETKERNEL_MSG_ROUTE6_ADD;
    route.hdr.size = sizeof(route);
    strcpy(route.iface, inst.get_name().c_str() + 5);
    route.metric = 150;
    route.flags = ROUTE6_FLAG_GATEWAY;
    route.hop_limit = adv->nd_ra_curhoplimit ? adv->nd_ra_curhoplimit : 64;

    struct sockaddr_nk dst;
    dst.nk_family = AF_NETKERNEL;
    strcpy(dst.path, "ipv6.rt");

    if (sendto(nkfd, (const void *) &route, sizeof(route), 0, (const sockaddr *) &dst,
               sizeof(dst)) < 0)
    {
        throw sys_error("Error adding local route");
    }
}

void configure_if(netctl::instance &instance)
{
    auto addr_config_type = instance.get_cfg()["ipv6"]["addrcfg_type"].get<std::string>();

    in6_addr addr = in6addr_any;

    if (addr_config_type == "slaac_mac")
    {
        configure_address_mac(instance, addr);
    }
    else if (addr_config_type == "slaac_random")
    {
        configure_address_random(instance, addr);
    }

    int sockfd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_ICMPV6);
    if (sockfd < 0)
    {
        throw sys_error("Could not create icmpv6 socket");
    }

    const int hops = 255;

    if (setsockopt(sockfd, SOL_IPV6, IPV6_UNICAST_HOPS, &hops, sizeof(hops)) < 0)
    {
        throw sys_error("Error setting hops for socket");
    }

    if (setsockopt(sockfd, SOL_IPV6, IPV6_MULTICAST_HOPS, &hops, sizeof(hops)) < 0)
    {
        throw sys_error("Error setting hops for socket");
    }

    icmp_filter filt;
    filt.code = ICMP_FILTER_CODE_UNSPEC;
    filt.type = ICMPV6_NEIGHBOUR_SOLICIT;

    if (setsockopt(sockfd, SOL_ICMPV6, ICMP_ADD_FILTER, &filt, sizeof(filt)) < 0)
    {
        throw sys_error("Error adding ICMPv6 filter");
    }

    filt.code = ICMP_FILTER_CODE_UNSPEC;
    filt.type = ICMPV6_NEIGHBOUR_ADVERT;

    if (setsockopt(sockfd, SOL_ICMPV6, ICMP_ADD_FILTER, &filt, sizeof(filt)) < 0)
    {
        throw sys_error("Error adding ICMPv6 filter");
    }

    /* 5.4.2.  Sending Neighbor Solicitation Messages - Before sending a Neighbor Solicitation,
     * an interface MUST join the all-nodes multicast address and the solicited-node multicast
     * address of the tentative address
     */

    join_multicast(all_nodes, sockfd, instance.get_if_index());
    join_multicast(solicited_node_address(addr), sockfd, instance.get_if_index());

    if (perform_dad(addr, sockfd, instance.get_if_index()) < 0)
    {
        /* TODO: How to respond to this properly? */
        throw std::runtime_error("duplicated address");
    }

    struct if_inet6_addr local_addr;
    local_addr.address = addr;
    local_addr.flags = INET6_ADDR_LOCAL;
    local_addr.prefix_len = 64;

    if (ioctl(instance.get_fd(), SIOADDINET6ADDR, &local_addr) < 0)
    {
        throw sys_error("SIOSETINET6");
    }

    join_multicast(solicited_node_address(addr), sockfd, instance.get_if_index());

    filt.code = ICMP_FILTER_CODE_UNSPEC;
    filt.type = ICMPV6_ROUTER_ADVERT;

    if (setsockopt(sockfd, SOL_ICMPV6, ICMP_ADD_FILTER, &filt, sizeof(filt)) < 0)
    {
        throw sys_error("Error adding ICMPv6 filter");
    }

    try
    {
        solicit_router(addr, sockfd, instance);
    }
    catch (std::exception &e)
    {
        /* It's alright if we don't have routers */
        std::cerr << std::format("{} failed to get a router: {}\n", instance.get_name(), e.what());
    }
}

} // namespace v6

} // namespace netctl
