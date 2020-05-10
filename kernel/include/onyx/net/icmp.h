/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _ONYX_NET_ICMP_H
#define _ONYX_NET_ICMP_H

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

#endif
