/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include <netinet/in.h>

#include <sys/socket.h>

#include <onyx/utils.h>
#include <onyx/net/ip.h>
#include <onyx/net/ethernet.h>
#include <onyx/net/netif.h>
#include <onyx/net/network.h>
#include <onyx/net/udp.h>
#include <onyx/net/arp.h>
#include <onyx/byteswap.h>
#include <onyx/net/tcp.h>
#include <onyx/cred.h>

size_t ipv4_get_packlen(void *info, struct packetbuf_proto **next, void **next_info);

struct packetbuf_proto __ipv4_pbf =
{
	.name = "ipv4",
	.get_len = ipv4_get_packlen
};

size_t ipv4_get_packlen(void *info, struct packetbuf_proto **next, void **next_info)
{
	/* In this function, info = netif */
	struct netif *n = static_cast<netif *>(info);

	*next = n->get_packetbuf_proto(n);
	*next_info = info;
	return sizeof(struct ip_header);
}

bool ipv4_needs_fragmentation(size_t packet_size, struct netif *netif)
{
	return packet_size > netif->mtu;
}

struct ipv4_fragment
{
	struct packetbuf_info *original_packet;
	struct packetbuf_info this_buf;
	uint16_t packet_off;
	uint16_t length;
	struct list_head list_node;
};

void ipv4_free_frags(struct list_head *frag_list)
{
	list_for_every_safe(frag_list)
	{
		struct ipv4_fragment *f = container_of(l, struct ipv4_fragment, list_node);

		if(f->packet_off != 0)
		{
			/* Don't free when it's the first fragment, because it uses a copy of the original packetbuf */
			packetbuf_free(&f->this_buf);
		}

		list_remove(l);
	}
}

struct ipv4_send_info
{
	uint32_t src_ip;
	uint32_t dest_ip;
	unsigned int type;
	unsigned int ttl;
	bool frags_following;
	uint16_t identification;
};

#define IPV4_OFF_TO_FRAG_OFF(x)		((x) >> 3)
#define IPV4_FRAG_OFF_TO_OFF(x)		((x) << 3)

void ipv4_setup_fragment(struct ipv4_send_info *info, struct ipv4_fragment *frag,
	struct ip_header *ip_header, struct netif *netif)
{
	bool frags_following = info->frags_following;

	memset(ip_header, 0, sizeof(struct ip_header));
	/* Source ip and dest ip have been already endian-swapped as to
	 * (ever so slightly) speed up fragmentation */
	ip_header->source_ip = info->src_ip;
	ip_header->dest_ip = info->dest_ip;
	ip_header->proto = info->type;
	ip_header->frag_info = htons((frags_following ? IPV4_FRAG_INFO_MORE_FRAGMENTS : 0)
                           | (IPV4_OFF_TO_FRAG_OFF(frag->packet_off)));
	ip_header->identification = htons(info->identification);
	ip_header->ttl = info->ttl;
	ip_header->total_len = htons(frag->length + sizeof(struct ip_header));
	ip_header->version = 4;
	ip_header->ihl = 5;
	ip_header->header_checksum = ipsum(ip_header, ip_header->ihl * sizeof(uint32_t));
}

int ipv4_create_fragments(struct list_head *frag_list, struct packetbuf_info *buf,
	size_t payload_size, struct ipv4_send_info *sinfo, struct netif *netif)
{
	/* Okay, let's split stuff in multiple IPv4 fragments */

	size_t total_packet_size = payload_size;
	(void) total_packet_size;
	uint16_t off = 0;

	/* Calculate the metadata's by subtracting payload_size from buf->length.
	 * This will give the size of, using a classic ethernet stack as an example,
	 * [ETHERNET HEADER] + [IP HEADER], which are for our purposes, the overhead of each packet.
	*/
	size_t packet_metadata_len = buf->length - payload_size;

	while(payload_size != 0)
	{
		struct ipv4_fragment *frag = static_cast<ipv4_fragment *>(zalloc(sizeof(*frag)));
		if(!frag)
		{
			ipv4_free_frags(frag_list);
			return -ENOMEM;
		}

		frag->original_packet = buf;

		/* Now we're computing this packet's length by adding the metadata's size and the
		 * remaining payload size, clamping it, and then subsequently subtracing the
		 * overhead of the metadata.
		*/
		size_t total_size = packet_metadata_len + payload_size;
		
		if(total_size > netif->mtu)
		{
			total_size = netif->mtu;
		}

		/* Sizes need to be 8-byte aligned so the next fragment's offset can be valid
		 * (fragment offsets are expressed in 8-byte units) */
		size_t this_payload_size =
			IPV4_FRAG_OFF_TO_OFF(IPV4_OFF_TO_FRAG_OFF(total_size - packet_metadata_len));

		frag->packet_off = off;
		frag->length = this_payload_size;

		bool first_packet = frag->packet_off == 0;
		if(first_packet)
		{
			/* If first fragment, copy the original buf's info and change the
			 * length; this should make this a faster operation.
			*/
			memcpy(&frag->this_buf, buf, sizeof(*buf));
			frag->this_buf.length = packet_metadata_len + this_payload_size;
		}
		else
		{
			frag->this_buf.length = this_payload_size;
	
			if(packetbuf_alloc(&frag->this_buf, &__ipv4_pbf, netif) < 0)
			{
				free(frag);
				ipv4_free_frags(frag_list);
				return -ENOMEM;
			}

			/* After allocating a new buffer, copy the packet */

			/* Note: This packetbuf_get_off is used to pop the ipv4 offset off the offset stack */
			packetbuf_get_off(&frag->this_buf);
	
			size_t segment_off = packet_metadata_len + off;
			uint8_t *new_packet_ptr = (uint8_t *) frag->this_buf.packet + packet_metadata_len;
			const uint8_t *old_packet_ptr = (const uint8_t *) buf->packet + segment_off;
			memcpy(new_packet_ptr, old_packet_ptr, frag->length);

		}

		struct ip_header *header = (struct ip_header *)((uint8_t *)
				frag->this_buf.packet + (packet_metadata_len - sizeof(struct ip_header)));
		
		sinfo->frags_following = !(payload_size == this_payload_size);
		ipv4_setup_fragment(sinfo, frag, header, netif);

		list_add_tail(&frag->list_node, frag_list);

		payload_size -= this_payload_size;
		off += this_payload_size;
	}

	return 0;
}

int ipv4_calculate_dstmac(unsigned char *destmac, uint32_t destip, struct netif *netif)
{
	if(destip == htonl(INADDR_BROADCAST))
	{
		/* INADDR_BROADCAST packets are sent to mac address ff:ff:ff:ff:ff:ff */
		memset(destmac, 0xff, 6);
	}
	else if(destip == htonl(INADDR_LOOPBACK))
	{
		/* INADDR_LOOPBACK packets are sent to the local NIC's mac */
		/* TODO: This is probably not correct. We most likely need to just send
		 * it to the other socket manually
		 */
		memcpy(destmac, netif->mac_address, 6);
	}
	else
	{
		/* Else, we need to send it to the router, so get the router's mac address */
		struct sockaddr_in *in = (struct sockaddr_in*) &netif->router_ip;
		if(arp_resolve_in(in->sin_addr.s_addr, destmac, netif) < 0)
			return errno = ENETUNREACH, -1;
	}

	return 0;
}

int ipv4_do_fragmentation(struct ipv4_send_info *sinfo, size_t payload_size,
                         struct packetbuf_info *buf, struct netif *netif)
{
	struct list_head frags = LIST_HEAD_INIT(frags);
	int st = ipv4_create_fragments(&frags, buf, payload_size, sinfo, netif);

	if(st < 0)
	{
		errno = -st;
		return -1;
	}

	unsigned char destmac[6] = {};
	if(ipv4_calculate_dstmac((unsigned char *) &destmac, sinfo->dest_ip, netif) < 0)
	{
		st = -1;
		goto out;
	}

	list_for_every(&frags)
	{
		struct ipv4_fragment *frag = container_of(l, struct ipv4_fragment, list_node);

		if(eth_send_packet((char *) &destmac, &frag->this_buf, PROTO_IPV4, netif) < 0)
		{
			st = -1;
			goto out;
		}
	}

out:
	ipv4_free_frags(&frags);

	return st;
}

uint16_t identification_counter = 0;

static uint16_t ipv4_allocate_id(void)
{
	return __atomic_fetch_add(&identification_counter, 1, __ATOMIC_CONSUME);
}

int ipv4_send_packet(uint32_t senderip, uint32_t destip, unsigned int type,
                     struct packetbuf_info *buf, struct netif *netif)
{
	size_t ip_header_off = packetbuf_get_off(buf);
	struct ip_header *ip_header = reinterpret_cast<struct ip_header *>(((char *) buf->packet) + ip_header_off);
	
	size_t payload_size = buf->length - ip_header_off - sizeof(struct ip_header);

	struct ipv4_send_info sinfo = {};
	/* Dest ip and sender ip are already in network order */
	sinfo.dest_ip = destip;
	sinfo.src_ip = senderip;
	sinfo.ttl = 64;
	sinfo.type = type;
	sinfo.frags_following = false;

	if(ipv4_needs_fragmentation(buf->length, netif))
	{
		/* TODO: Support ISO(IP segmentation offloading) */
		sinfo.identification = ipv4_allocate_id();
		return ipv4_do_fragmentation(&sinfo, payload_size, buf, netif);
	}

	/* Let's reuse code by creating a single fragment struct on the stack */
	struct ipv4_fragment frag;
	frag.length = payload_size;
	frag.packet_off = 0;

	ipv4_setup_fragment(&sinfo, &frag, ip_header, netif);

	unsigned char destmac[6] = {};
	if(ipv4_calculate_dstmac((unsigned char *) &destmac, destip, netif) < 0)
	{
		return -1;
	}

	return eth_send_packet((char*) &destmac, buf, PROTO_IPV4, netif);
}

/* TODO: Possibly, these basic checks across ethernet.c, ip.c, udp.c, tcp.cpp aren't enough */
bool ipv4_valid_packet(struct ip_header *header, size_t size)
{
	if(ntohs(header->total_len) > size)
		return false;
	if(sizeof(struct ip_header) > size)
		return false;
	return true;
}

void ipv4_handle_packet(struct ip_header *header, size_t size, struct netif *netif)
{
	struct ip_header *usable_header = static_cast<ip_header *>(memdup(header, size));

	if(!ipv4_valid_packet(usable_header, size))
		return;

	if(header->proto == IPV4_UDP)
		udp_handle_packet(usable_header, size, netif);
	else if(header->proto == IPV4_TCP)
	{
		tcp_handle_packet(usable_header, size, netif);
	}

	free(usable_header);
}

struct socket *ipv4_create_socket(int type, int protocol)
{
	switch(type)
	{
		case SOCK_DGRAM:
		{
			switch(protocol)
			{
				case PROTOCOL_UDP:
					return udp_create_socket(type);
				default:
					return NULL;
			}
		}

		case SOCK_STREAM:
		{
			case PROTOCOL_TCP:
				return tcp_create_socket(type);
		}
	}
	return NULL;
}

bool inet_has_permission_for_port(in_port_t port)
{
	port = ntohs(port);

	if(port >= inet_min_unprivileged_port)
		return true;
	
	struct creds *c = creds_get();

	if(c->euid == 0)
		return true;
	
	creds_put(c);

	return false;
}
