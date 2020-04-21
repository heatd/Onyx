/*
* Copyright (c) 2020 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _LIBUUID_UUID_H
#define _LIBUUID_UUID_H

typedef unsigned char uuid_t[16];

#ifdef __cplusplus
extern "C" {
#endif

void uuid_generate_time(uuid_t out);
int uuid_generate_time_safe(uuid_t out);
void uuid_generate(uuid_t out);
void uuid_generate_random(uuid_t out);

#ifdef __cplusplus
}
#endif

#endif
