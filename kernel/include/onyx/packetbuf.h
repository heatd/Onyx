/*
* Copyright (c) 2020 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _ONYX_PACKETBUF_H
#define _ONYX_PACKETBUF_H

#include <stddef.h>

/* packetbuf_proto - implemented by every protocol layer in order to
 * figure out the size of the final packet
*/

struct packetbuf_proto
{
	const char *name;
	/* get_len - called to get its overhead - info is used if needed, else NULL.
	 * Returns: its overhead as a return value, the next proto if any in *next and
	 * the next info arg in *next_info.
	*/
	size_t (*get_len)(void *info, struct packetbuf_proto **next, void **next_info);
};

struct packetbuf_info
{
	void *packet;
	size_t length;
	size_t *offsets;
	size_t nr_offs;
	size_t buf_count;
	size_t current_off;
};

#ifdef __cplusplus
extern "C" {
#endif

int packetbuf_alloc(struct packetbuf_info *pinfo, struct packetbuf_proto *first, void *info);
void packetbuf_free(struct packetbuf_info *info);

static inline size_t packetbuf_get_off(struct packetbuf_info *info)
{
	return info->offsets[info->current_off++];
}

#ifdef __cplusplus
}
#endif

#endif