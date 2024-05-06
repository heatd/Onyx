/*
 * Copyright (c) 2020 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 */
#ifndef _LIBUUID_UUID_H
#define _LIBUUID_UUID_H

#include <sys/types.h>

typedef unsigned char uuid_t[16];

#ifdef __cplusplus
extern "C"
{
#endif

#define UUID_STR_LEN 37

void uuid_generate_time(uuid_t out);
int uuid_generate_time_safe(uuid_t out);
void uuid_generate(uuid_t out);
void uuid_generate_random(uuid_t out);
void uuid_unparse(const uuid_t uu, char *out);
void uuid_unparse_upper(const uuid_t uu, char *out);
void uuid_unparse_lower(const uuid_t uu, char *out);
int uuid_is_null(uuid_t uu);
int uuid_parse(char *in, uuid_t uu);

#ifdef __cplusplus
}
#endif

#endif
