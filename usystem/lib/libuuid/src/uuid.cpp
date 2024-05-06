/*
 * Copyright (c) 2020 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 */

#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <cstring>

#include <netpacket/packet.h>
#include <uuid/uuid.h>

struct uuid_format
{
    std::uint32_t time_low;
    std::uint16_t time_mid;
    std::uint16_t time_hi_and_version;
    std::uint8_t clk_seq_hi_and_res;
    std::uint8_t clk_seq_low;
    std::uint8_t node_id[6];
} __attribute__((packed));

union uuid_representation {
    struct uuid_format format;
    uuid_t raw;
};

static_assert(sizeof(uuid_representation) == sizeof(uuid_format));
static_assert(sizeof(uuid_format) == sizeof(uuid_t));
static_assert(sizeof(uuid_t) == 16);

void uuid_generate_time(uuid_t out)
{
    uuid_generate_time_safe(out);
}

constexpr unsigned int version_shift = 4;
constexpr unsigned int version_mask = (0b1111 << version_shift);

static void set_version_and_variant(uuid_representation *uuid, unsigned int version,
                                    unsigned int variant)
{
    uuid->format.time_hi_and_version &= ~version_mask;
    uuid->format.time_hi_and_version |= version << version_shift;

    // TODO: Doesn't work with variants != 1(but who uses those anyway?)
    uuid->format.clk_seq_hi_and_res |= (variant << 5);
}

int get_mac_address(std::array<unsigned char, 6> &mac)
{
    int st = -EIO;
    ifaddrs *addrs;
    if (getifaddrs(&addrs) < 0)
        return st;

    for (ifaddrs *a = addrs; a != nullptr; a = a->ifa_next)
    {
        if (a->ifa_flags & IFF_LOOPBACK)
            continue;

        if (a->ifa_addr->sa_family == AF_PACKET)
        {
            sockaddr_ll addr;
            std::memcpy((void *) &addr, (const void *) a->ifa_addr, sizeof(sockaddr_ll));

            // Skip if its not a MAC address
            if (addr.sll_halen != 6)
                continue;
            std::memcpy(mac.data(), addr.sll_addr, addr.sll_halen);
            st = 0;
            break;
        }
    }

    freeifaddrs(addrs);

    return st;
}

static void get_entropy(void *buf, size_t len)
{
    if (syscall(SYS_getrandom, buf, len) < 0)
        std::abort();
}

int uuid_generate_time_safe(uuid_t out)
{
    std::array<unsigned char, 6> mac;
    if (get_mac_address(mac) < 0)
    {
        // As specified by the RFC, get a random address and set the multicast bit
        // which is the least significant of the first octet

        get_entropy(mac.data(), mac.size());
        mac[0] |= (1 << 0);
    }

    timespec time;

    if (clock_gettime(CLOCK_REALTIME, &time) < 0)
        std::abort();

    time_t seconds_since_gregorian = time.tv_sec + 12219292800;

    // Convert seconds into 100 nanosecond units and add tv_nsec/10
    std::uint64_t timestamp = (seconds_since_gregorian * 10000000) + (time.tv_nsec / 10);
    uuid_representation *v1 = (uuid_representation *) out;
    std::memcpy(&v1->format.node_id, mac.data(), mac.size());
    v1->format.time_low = (std::uint32_t) timestamp;
    v1->format.time_mid = (std::uint16_t)(timestamp >> 32);
    v1->format.time_hi_and_version = (std::uint16_t)(timestamp >> 48);

    set_version_and_variant(v1, 1, 1);
    return 0;
}

void uuid_generate(uuid_t out)
{
    uuid_generate_random(out);
}

void uuid_generate_random(uuid_t out)
{
    uuid_representation *v4 = (uuid_representation *) out;
    get_entropy((void *) v4, sizeof(uuid_t));

    set_version_and_variant(v4, 4, 1);
}

int uuid_is_null(uuid_t uu)
{
    for (int i = 0; i < 16; i++)
        if (uu[i] != 0)
            return 0;
    return 1;
}

void uuid_clear(uuid_t uu)
{
    memset(uu, 0, 16);
}
