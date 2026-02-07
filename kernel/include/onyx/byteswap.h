/*
 * Copyright (c) 2020 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 */
#ifndef _ONYX_BYTESWAP_H
#define _ONYX_BYTESWAP_H

#include <stdint.h>

#include <onyx/compiler.h>
#include <onyx/types.h>

#define bswap16(x) __builtin_bswap16((__force u16) x)
#define bswap32(x) __builtin_bswap32((__force u32) x)
#define bswap64(x) __builtin_bswap64((__force u64) x)

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__

static inline uint32_t htonl(uint32_t host)
{
    return bswap32(host);
}

static inline uint16_t htons(uint16_t host)
{
    return bswap16(host);
}

static inline uint32_t ntohl(uint32_t net)
{
    return bswap32(net);
}

static inline uint16_t ntohs(uint16_t net)
{
    return bswap16(net);
}

#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__

static inline uint32_t htonl(uint32_t host)
{
    return host;
}

static inline uint16_t htons(uint16_t host)
{
    return host;
}

static inline uint32_t ntohl(uint32_t net)
{
    return net;
}

static inline uint16_t ntohs(uint16_t net)
{
    return net;
}

#else

#error "Unknown byte order"

#endif

#define ntoh32(x) ntohl(x)
#define ntoh16(x) ntohs(x)
#define hton32(x) htonl(x)
#define hton16(x) htons(x)

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define be16_to_cpu(be)  ((u16) bswap16(be))
#define be32_to_cpu(be)  ((u32) bswap32(be))
#define be64_to_cpu(be)  ((u64) bswap64(be))
#define le16_to_cpu(le)  ((__force u16) (le))
#define le32_to_cpu(le)  ((__force u32) (le))
#define le64_to_cpu(le)  ((__force u64) (le))
#define cpu_to_le16(val) ((__force __le16) (val))
#define cpu_to_le32(val) ((__force __le32) (val))
#define cpu_to_le64(val) ((__force __le64) (val))
#define cpu_to_be16(val) ((__force __be16) bswap16(val))
#define cpu_to_be32(val) ((__force __be32) bswap32(val))
#define cpu_to_be64(val) ((__force __be64) bswap64(val))
#else
#define le16_to_cpu(le)  ((u16) bswap16(le))
#define le32_to_cpu(le)  ((u32) bswap32(le))
#define le64_to_cpu(le)  ((u64) bswap64(le))
#define be16_to_cpu(be)  ((__force u16) (be))
#define be32_to_cpu(be)  ((__force u32) (be))
#define be64_to_cpu(be)  ((__force u64) (be))
#define cpu_to_be16(val) ((__force __be16) (val))
#define cpu_to_be32(val) ((__force __be32) (val))
#define cpu_to_be64(val) ((__force __be64) (val))
#define cpu_to_le16(val) ((__force __le16) bswap16(val))
#define cpu_to_le32(val) ((__force __le32) bswap32(val))
#define cpu_to_le64(val) ((__force __le64) bswap64(val))
#endif

#endif
