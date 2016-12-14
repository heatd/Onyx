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

#include <kernel/log.h>
#include <kernel/dns.h>
#include <kernel/network.h>
static uint32_t server_ip = 0;
extern void parse_ipnumber_to_char_array(uint32_t, unsigned char *);
void dns_set_server_ip(uint32_t ip)
{
	unsigned char ip_b[4] = {0};
	parse_ipnumber_to_char_array(ip, (unsigned char*) &ip_b);
	LOG("dns", "new dns server: %u.%u.%u.%u\n", ip_b[0], ip_b[1], ip_b[2], ip_b[3]);
	server_ip = ip;
}
int dns_sock = -1;
void dns_test()
{
	INFO("dns", "testing\n");
	dns_sock = socket(AF_INET, SOCK_DGRAM, 0);
	if(dns_sock == -1)
		panic("Failed to create a sock for the dns subsystem\n");
	// Bind a socket with the dhcp port numbers and the broadcast IP
	if(bind(dns_sock, 53, server_ip, 53))
		panic("Failed to bind a socket for the dhcp client!\n");*/
}
