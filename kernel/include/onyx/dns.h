/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _KERNEL_DNS_H
#define _KERNEL_DNS_H

#include <stdint.h>

/* According to RFC 1035 */
struct dns
{
	uint16_t dns_id;
	uint16_t flags;
	uint16_t qdcount;
	uint16_t ancount;
	uint16_t nscount;
	uint16_t arcount;
	char names[0]; /* 
			* Each domain name has a respective length octet before each token, substituting the '.' 
			* After the domain name, it contains a 2 octet value specifying the type of the query and 
			* a 2 octet value which specifies the class of the query 
			*/
};

typedef struct hn
{
	const char *name;
	uint32_t address;
	struct hn *next;
} hostname_t;

typedef struct
{
	size_t size;
	hostname_t **buckets;
} hostname_hashtable_t;

void dns_set_server_ip(uint32_t ip);
void dns_init();
uint32_t dns_send_request(const char *name);
uint32_t dns_resolve_host(const char *name);
void dns_fill_hashtable(int hash, const char *name, uint32_t address);
int dns_hash_string(const char *name);

#endif
