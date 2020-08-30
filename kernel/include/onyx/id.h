/*
* Copyright (c) 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _KERNEL_ID_H
#define _KERNEL_ID_H
#include <stdint.h>

#ifndef __cplusplus
#include <stdatomic.h>
#endif

struct ids
{
	char *name;
#ifndef __cplusplus
	atomic_uintmax_t id;
	atomic_uintmax_t upper_limit;
#else
	uintmax_t id, upper_limit;
#endif
	struct ids *next;
};

#ifdef __cplusplus
extern "C" {
#endif

struct ids *idm_add(const char *name, uintmax_t min_id, uintmax_t upper_limit);
uintmax_t idm_get_id(struct ids *id);
uintmax_t idm_get_id_from_name(const char *name);
const char *idm_get_device_letter(struct ids *ids);

#ifdef __cplusplus
}
#endif

#endif
