/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include <onyx/log.h>
#include <onyx/dns.h>
#include <onyx/network.h>
#include <onyx/crc32.h>
#include <onyx/panic.h>

#define DEFAULT_SIZE 256

static hostname_hashtable_t *hashtable = NULL;

void dns_init(void)
{
	/* Allocate and zero-out a hashtable */
	hashtable = malloc(sizeof(hostname_hashtable_t));
	if(!hashtable)
		panic("Error while allocating the dns hashtable: No memory\n");

	memset(hashtable, 0, sizeof(hostname_hashtable_t));
	hashtable->size = DEFAULT_SIZE;
	hashtable->buckets = malloc(DEFAULT_SIZE * sizeof(void*));
	if(!hashtable->buckets)
		panic("oom while allocating a hashtable bucket\n");
	memset(hashtable->buckets, 0, sizeof(void*) * DEFAULT_SIZE);
}
int dns_hash_string(const char *name)
{
	return crc32_calculate((uint8_t *) name, strlen(name)) % DEFAULT_SIZE;
}
void dns_fill_hashtable(int hash, const char *name, uint32_t address)
{
	hostname_t *host = hashtable->buckets[hash];
	
	hostname_t *prev = NULL;
	for(; host; host = host->next)
		prev = host;
	
	host = malloc(sizeof(hostname_t));
	if(!host)
		return errno = ENOMEM, (void) 0;
	memset(host, 0, sizeof(hostname_t));

	if(!hashtable->buckets[hash])
		hashtable->buckets[hash] = host;
	if(prev)
		prev->next = host;
	host->name = name;
	host->address = address;
}
#if 0
static uint32_t server_ip = 0;

extern void parse_ipnumber_to_char_array(uint32_t, unsigned char *);
extern uint32_t parse_char_array_to_ip_number(unsigned char*);
void dns_set_server_ip(uint32_t ip)
{
	unsigned char ip_b[4] = {0};
	parse_ipnumber_to_char_array(ip, (unsigned char*) &ip_b);
	LOG("dns", "new dns server: %u.%u.%u.%u\n", ip_b[0], ip_b[1], ip_b[2], ip_b[3]);
	server_ip = ip;
}
int dns_sock = -1;
void dns_init()
{
	INFO("dns", "initializing\n");
	dns_sock = socket(AF_INET, SOCK_DGRAM, 0);
	if(dns_sock == -1)
		panic("Failed to create a sock for the dns subsystem\n");
	// Bind a socket with the dhcp port numbers and the broadcast IP
	if(bind(dns_sock, 53, LITTLE_TO_BIG32(server_ip), 53))
		panic("Failed to bind a socket for the dhcp client!\n");
	
	/* Allocate and zero-out a hashtable */
	hashtable = malloc(sizeof(hostname_hashtable_t));
	if(!hashtable)
		panic("Error while allocating the dns hashtable: No memory\n");

	memset(hashtable, 0, sizeof(hostname_hashtable_t));
	hashtable->size = DEFAULT_SIZE;
	hashtable->buckets = malloc(DEFAULT_SIZE * sizeof(void*));
	if(!hashtable->buckets)
		panic("oom while allocating a hashtable bucket\n");
	memset(hashtable->buckets, 0, sizeof(void*) * DEFAULT_SIZE);
}
uint32_t dns_resolve_host(const char *name)
{
	int hash = dns_hash_string(name);
	/* See if this host is already on the hashtable, if so just return the contents */
	hostname_t *host = hashtable->buckets[hash];
	for(; host; host = host->next)
	{
		if(!strcmp((char*) host->name,(char*) name))
			return host->address;
	}
	/* else just perform a normal dns request and fill the hashtable after that */
	uint32_t address = dns_send_request(name);
	if(address == (uint32_t) -1 && errno == ENOMEM)
		return -1;
	dns_fill_hashtable(hash, name, address);

	return address;
}
uint32_t dns_send_request(const char *name)
{
	size_t size = sizeof(struct dns) + strlen(name) + 6;
	/* The size of the allocate buffer = size of the dns header + the length of the name + 1 bytes for the beginning token's size
	+ 1 byte for the terminating zero + 4 bytes for the remaining QTYPE and QCLASS */

	/* Allocate and zero it out */
	struct dns *request = malloc(size);
	if(!request)
		return errno = ENOMEM, -1;
	memset(request, 0, size);
	/* TODO: When we support concurent network operations(we currently don't), make sure we use the dns_id field for something */
	request->dns_id = 0xFEFE;
	
	request->flags = 1;
	request->qdcount = LITTLE_TO_BIG16(1);
	char *s = (char*) &request->names;
	*s = 3;
	s++;
	while(*name != '\0')
	{
		if(*name == '.')
		{
			unsigned char len = 0;
			char *next_token = (char*) strchr((char*) name+1, '.');
			if(!next_token)
				len = strlen(name) - 1;
			else
				len = next_token - name - 1;
			*s++ = len;
			name++;
		}
		else
		{
			*s++ = *name++;
		}
	}
	s++;
	uint16_t *i = (uint16_t *) s;
	*i++ = LITTLE_TO_BIG16(1);
	*i = LITTLE_TO_BIG16(1);
	send(dns_sock, (const void*) request, size);
	
	/* Free up request, and see if we get a response */
	free(request);
	struct dns *answer = NULL;
	recv(dns_sock, (void **) &answer);
	unsigned char *b = (unsigned char*)&answer->names + size - sizeof(struct dns);
again:;
	uint16_t in = LITTLE_TO_BIG16(*((uint16_t*)(b + 2)));
	if( in != 1)
	{
		b += 14;
		goto again;
	}
	b+= 12;

	free(answer);
	return parse_char_array_to_ip_number(b);
}
#endif
