/*
 * Copyright (c) 2017 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 */

#ifndef _ONYX_CRYPT_SHA256_H
#define _ONYX_CRYPT_SHA256_H

#include <stdint.h>

struct sha256_state
{
    uint64_t length;
    uint32_t state[8], curlen;
    uint8_t buf[64];
};

void sha256_init(struct sha256_state *md);
int sha256_process(struct sha256_state *md, const unsigned char *in, unsigned long inlen);
int sha256_done(struct sha256_state *md, unsigned char *out);

#endif
