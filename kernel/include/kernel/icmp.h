/*----------------------------------------------------------------------
 * Copyright (C) 2016 Pedro Falcato
 *
 * This file is part of Spartix, and is made available under
 * the terms of the GNU General Public License version 2.
 *
 * You can redistribute it and/or modify it under the terms of the GNU
 * General Public License version 2 as published by the Free Software
 * Foundation.
 *----------------------------------------------------------------------*/
#ifndef _KERNEL_ICMP_H
#define _KERNEL_ICMP_H

#include <stdint.h>

#define ICMP_TYPE_ECHO_REPLY 0
#define ICMP_TYPE_ECHO_REQUEST 8

typedef struct icmp
{
	uint8_t type;
	uint8_t code;
	uint16_t checksum;
	uint32_t rest;
} icmp_header_t;

void icmp_init();
int icmp_ping(uint32_t ip, int times);
#endif
