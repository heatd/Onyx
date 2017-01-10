/*----------------------------------------------------------------------
 * Copyright (C) 2016, 2017 Pedro Falcato
 *
 * This file is part of Spartix, and is made available under
 * the terms of the GNU General Public License version 2.
 *
 * You can redistribute it and/or modify it under the terms of the GNU
 * General Public License version 2 as published by the Free Software
 * Foundation.
 *----------------------------------------------------------------------*/
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include <kernel/network.h>
#include <kernel/icmp.h>
#include <kernel/ip.h>
#include <kernel/log.h>

int icmp_socket = -1;
void icmp_init()
{
	INFO("icmp", "initializing\n");
	icmp_socket = socket(AF_INET, SOCK_RAW, IPV4_ICMP);
	if(icmp_socket == -1)
	{
		ERROR("icmp", "failed to create socket\n");
		return;
	}
}
int _icmp_ping()
{
	icmp_header_t *hdr = malloc(sizeof(icmp_header_t) + 30);
	if(!hdr)
		return 1;
	memset(hdr, 0, sizeof(icmp_header_t) + 30);
	hdr->type = ICMP_TYPE_ECHO_REQUEST;
	hdr->rest = 0x100FEFE;
	hdr->checksum = internetchksum(hdr, sizeof(icmp_header_t) + 30);
	send(icmp_socket, hdr, sizeof(icmp_header_t) + 30);
	free(hdr);
	hdr = NULL;
	recv(icmp_socket, (void**) &hdr);
	if(hdr->type && hdr->rest == 0x100FEFE)
	{
		/* If hdr->type != ICMP_TYPE_ECHO_REPLY and the identification number is identical to the sent one,
		 we had an error, so just return the error code */
		uint8_t code = hdr->code;
		free(hdr);
		return code;
	}
	return 0;
}
int icmp_ping(uint32_t ip, int times)
{
	bind(icmp_socket, 0, ip, 0);
	for(int i = 0; i < times; i++)
	{
		int i = _icmp_ping();
		if(i)
			return i;
	}
	return 0;
}
