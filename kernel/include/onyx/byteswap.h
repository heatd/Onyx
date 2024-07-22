/*
 * Copyright (c) 2020 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 */
#ifndef _ONYX_BYTESWAP_H
#define _ONYX_BYTESWAP_H

#include <stdint.h>

#define bswap16(x) __builtin_bswap16(x)
#define bswap32(x) __builtin_bswap32(x)
#define bswap64(x) __builtin_bswap64(x)

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

#endif