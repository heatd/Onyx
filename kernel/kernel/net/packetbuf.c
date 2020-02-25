/*
* Copyright (c) 2020 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#include <stdlib.h>
#include <errno.h>


#include <stdio.h>

#include <onyx/packetbuf.h>
#include <onyx/compiler.h>

/* Let's use 3 since it fits perfectly with (UDP/TCP), IPv4, ETH - it's the main packet stack */

#define BUF_COUNT_INCREMENT			3
static int __put_in_bufs(struct packetbuf_info *info, size_t len)
{
	
	if(unlikely(info->nr_offs >= info->buf_count))
	{
		size_t new_bufcount = info->buf_count + 3;
		void *new_ptr = realloc(info->offsets, sizeof(size_t) * new_bufcount);
		if(!new_ptr)
			return -1;
		info->offsets = new_ptr;
		info->buf_count = new_bufcount;
	}

	info->offsets[info->nr_offs] = len;
	info->nr_offs++;

	return 0;
}

int packetbuf_alloc(struct packetbuf_info *pinfo, struct packetbuf_proto *first, void *info)
{
	struct packetbuf_proto *curr_proto = first;

	while(curr_proto != NULL)
	{
		/* We use these two variables so get_len is easier to write
		 * (don't need to make sure that *next and *next_info are NULL at the end). */
		void *new_info = NULL;
		struct packetbuf_proto *next_proto = NULL;

		size_t len = curr_proto->get_len(info, &next_proto, &new_info);
	
		if(__put_in_bufs(pinfo, len) < 0)
			return -ENOMEM; 

		info = new_info;
		curr_proto = next_proto;
	}

	
	size_t proto_length = 0;

	for(size_t i = 0; i < pinfo->nr_offs; i++)
		proto_length += pinfo->offsets[i];
	
	pinfo->length += proto_length;

	size_t size_until_now = 0;

	for(long i = pinfo->nr_offs - 1; i >= 0; i--)
	{
		size_t this_layer_len = pinfo->offsets[i];
		pinfo->offsets[i] = size_until_now;
		size_until_now += this_layer_len;
	}

	pinfo->packet = malloc(pinfo->length);
	if(!pinfo->packet)
		return -1;

	return 0;
}

void packetbuf_free(struct packetbuf_info *info)
{
	free(info->packet);
	free(info->offsets);
}
