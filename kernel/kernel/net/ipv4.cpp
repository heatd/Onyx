/*
* Copyright (c) 2016-2020 Pedro Falcato
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

#include <onyx/random.h>
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

namespace ip
{

namespace v4
{

bool needs_fragmentation(size_t packet_size, struct netif *netif)
{
	return packet_size > netif->mtu;
}

struct fragment
{
	packetbuf *original_packet;
	packetbuf *this_buf;
	uint16_t packet_off;
	uint16_t length;
	struct list_head list_node;
};

void free_frags(struct list_head *frag_list)
{
	list_for_every_safe(frag_list)
	{
		struct fragment *f = container_of(l, struct fragment, list_node);

		if(f->packet_off != 0)
		{
			/* Don't free when it's the first fragment, because it uses a copy of the original packetbuf */
			// packetbuf_free(&f->this_buf);
		}

		list_remove(l);

		free(f);
	}
}

struct send_info
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

void setup_fragment(struct send_info *info, struct fragment *frag,
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

int create_fragments(struct list_head *frag_list, packetbuf *buf,
	size_t payload_size, struct send_info *sinfo, struct netif *netif)
{
	/* Okay, let's split stuff in multiple IPv4 fragments */
	/* TODO: Implement with packetbufs */
	return -EIO;
#if 0
	size_t total_packet_size = payload_size;
	(void) total_packet_size;
	uint16_t off = 0;

	/* Calculate the metadata's by subtracting payload_size from buf->length.
	 * This will give the size of, using a classic ethernet stack as an example,
	 * [ETHERNET HEADER] + [IP HEADER], which are for our purposes, the overhead of each packet.
	*/
	size_t packet_metadata_len = buf->length() - payload_size;

	while(payload_size != 0)
	{
		struct fragment *frag = static_cast<fragment *>(zalloc(sizeof(*frag)));
		if(!frag)
		{
			free_frags(frag_list);
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
			frag->this_buflength = packet_metadata_len + this_payload_size;
		}
		else
		{
			frag->this_buf.length = this_payload_size;
	
			if(packetbuf_alloc(&frag->this_buf, &__ipv4_pbf, netif) < 0)
			{
				free(frag);
				free_frags(frag_list);
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
		setup_fragment(sinfo, frag, header, netif);

		list_add_tail(&frag->list_node, frag_list);

		payload_size -= this_payload_size;
		off += this_payload_size;
	}

	return 0;
#endif

}

int calculate_dstmac(unsigned char *destmac, uint32_t destip, struct netif *netif)
{
	if(destip == htonl(INADDR_BROADCAST))
	{
		/* INADDR_BROADCAST packets are sent to mac address ff:ff:ff:ff:ff:ff */
		memset(destmac, 0xff, 6);
	}
	else if(destip == htonl(INADDR_LOOPBACK))
	{
		/* INADDR_LOOPBACK packets are not sent, so we're zero'ing it */
		memset(destmac, 0, 6);
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

int do_fragmentation(struct send_info *sinfo, size_t payload_size,
                         packetbuf *buf, struct netif *netif)
{
	struct list_head frags = LIST_HEAD_INIT(frags);
	int st = create_fragments(&frags, buf, payload_size, sinfo, netif);

	if(st < 0)
	{
		errno = -st;
		return -1;
	}

	unsigned char destmac[6] = {};
	if(calculate_dstmac((unsigned char *) &destmac, sinfo->dest_ip, netif) < 0)
	{
		st = -1;
		goto out;
	}

	list_for_every(&frags)
	{
		struct fragment *frag = container_of(l, struct fragment, list_node);

		if(eth_send_packet((char *) &destmac, frag->this_buf, PROTO_IPV4, netif) < 0)
		{
			st = -1;
			goto out;
		}
	}

out:
	free_frags(&frags);

	return st;
}

uint16_t identification_counter = 0;

static uint16_t allocate_id(void)
{
	return __atomic_fetch_add(&identification_counter, 1, __ATOMIC_CONSUME);
}

int send_packet(uint32_t senderip, uint32_t destip, unsigned int type,
                     packetbuf *buf, struct netif *netif)
{
	ip_header *iphdr = (ip_header *) buf->push_header(sizeof(ip_header));

	size_t payload_size = buf->length() - sizeof(struct ip_header);

	struct send_info sinfo = {};
	/* Dest ip and sender ip are already in network order */
	sinfo.dest_ip = destip;
	sinfo.src_ip = senderip;
	sinfo.ttl = 64;
	sinfo.type = type;
	sinfo.frags_following = false;

	if(needs_fragmentation(buf->length(), netif))
	{
		/* TODO: Support ISO(IP segmentation offloading) */
		sinfo.identification = allocate_id();
		return do_fragmentation(&sinfo, payload_size, buf, netif);
	}

	/* Let's reuse code by creating a single fragment struct on the stack */
	struct fragment frag;
	frag.length = payload_size;
	frag.packet_off = 0;
	buf->net_header = (unsigned char *) iphdr;

	setup_fragment(&sinfo, &frag, iphdr, netif);

	unsigned char destmac[6] = {};
	if(calculate_dstmac((unsigned char *) &destmac, destip, netif) < 0)
	{
		return -1;
	}

	return eth_send_packet((char*) &destmac, buf, PROTO_IPV4, netif);
}

/* TODO: Possibly, these basic checks across ethernet.c, ip.c, udp.c, tcp.cpp aren't enough */
bool valid_packet(struct ip_header *header, size_t size)
{
	if(ntohs(header->total_len) > size)
		return false;
	if(sizeof(struct ip_header) > size)
		return false;
	return true;
}

void handle_packet(struct ip_header *header, size_t size, struct netif *netif)
{
	struct ip_header *usable_header = static_cast<ip_header *>(memdup(header, size));

	if(!valid_packet(usable_header, size))
		return;

	uint16_t len = htons(usable_header->total_len);

	if(header->proto == IPV4_UDP)
		udp_handle_packet(usable_header, len, netif);
	else if(header->proto == IPV4_TCP)
	{
		tcp_handle_packet(usable_header, len, netif);
	}

	free(usable_header);
}

socket *choose_protocol_and_create(int type, int protocol)
{
	switch(type)
	{
		case SOCK_DGRAM:
		{
			switch(protocol)
			{
				case IPPROTO_UDP:
					return udp_create_socket(type);
				default:
					return nullptr;
			}
		}

		case SOCK_STREAM:
		{
			case IPPROTO_TCP:
				return tcp_create_socket(type);
			default:
				return nullptr;
		}
	}
}

/* Use linux's ephemeral ports */
static constexpr in_port_t ephemeral_upper_bound = 61000;
static constexpr in_port_t ephemeral_lower_bound = 32768;

in_port_t allocate_ephemeral_port(netif *netif, sockaddr_in &in, inet_socket *sock)
{
	while(true)
	{
		in_port_t port = htons(static_cast<in_port_t>(arc4random_uniform(
			 ephemeral_upper_bound - ephemeral_lower_bound)) + ephemeral_lower_bound);

		in.sin_port = port;
	
		const socket_id id{sock->proto, sa_generic(in), sa_generic(in)};
		
		netif_lock_socks(id, netif);

		auto sock = netif_get_socket(id, netif, GET_SOCKET_CHECK_EXISTANCE | GET_SOCKET_UNLOCKED);

		if(!sock)
			return port;
		else
		{
			/* Let's try again, boys */
			netif_unlock_socks(id, netif);
		}
	}

}

int proto_family::bind_one(sockaddr_in *in, netif *netif, inet_socket *sock)
{
	const socket_id id(sock->proto, sa_generic(*in), sa_generic(*in));

	if(in->sin_port != 0)
	{
		if(!inet_has_permission_for_port(in->sin_port))
			return -EPERM;

		netif_lock_socks(id, netif);
		/* Check if there's any socket bound to this address yet */
		if(netif_get_socket(id, netif, GET_SOCKET_CHECK_EXISTANCE | GET_SOCKET_UNLOCKED))
		{
			netif_unlock_socks(id, netif);
			return -EADDRINUSE;
		}
	}
	else
	{
		/* Lets try to allocate a new ephemeral port for us */
		allocate_ephemeral_port(netif, *in, sock);
	}

	/* Note that we keep doing this memcpy in each bind_one() just so the socket
	 * hashes properly - the state of the socket(whether it's bound or not) entirely depends on
	 * sock->bound = true in proto_family::bind()
	 */
	memcpy(&sock->src_addr, in, sizeof(struct sockaddr));

	/* Note: locks need to be held */
	bool success = netif_add_socket(sock, netif, ADD_SOCKET_UNLOCKED);

	netif_unlock_socks(id, netif);

	return success ? 0 : -ENOMEM;
}

static constexpr bool is_bind_any(in_addr_t addr)
{
	/* For historical reasons, INADDR_ANY == INADDR_BROADCAST (linux's ip(7)).
	 * Linux isn't alone in this and we should strive for compatibility.
	 */
	return addr == INADDR_ANY || addr == INADDR_BROADCAST;
}

int proto_family::bind(sockaddr *addr, socklen_t len, inet_socket *sock)
{
	if(len != sizeof(sockaddr_in))
		return -EINVAL;

	sockaddr_in *in = (sockaddr_in *) addr;

	int st = 0;

	if(!sock->validate_sockaddr_len_pair(addr, len))
		return -EINVAL;

	if(!is_bind_any(in->sin_addr.s_addr))
	{
		auto nif = netif_get_from_addr(addr, AF_INET);
		if(!nif)
		{
			return -EADDRNOTAVAIL;
		}

		st = bind_one(in, nif, sock);
	}
	else
	{
		auto list_start = netif_lock_and_get_list();
		
		list_for_every(list_start)
		{
			auto netif = container_of(l, struct netif, list_node);

			st = bind_one(in, netif, sock);

			if(st < 0)
			{
				auto stop = l;

				list_for_every(list_start)
				{
					if(l == stop)
						break;
					panic("Implement socket un-binding");
				}

				netif_unlock_list();
				return st;
			}
		}

		netif_unlock_list();
	}

	if(st < 0)
		return st;
	
	sock->bound = true;
	return 0;
}

int proto_family::bind_any(inet_socket *sock)
{
	sockaddr_in in = {};
	in.sin_family = AF_INET;
	in.sin_addr.s_addr = INADDR_ANY;
	in.sin_port = 0;

	return bind((sockaddr *) &in, sizeof(sockaddr_in), sock);
}

void proto_family::unbind_one(netif *nif, inet_socket *sock)
{
	assert(netif_remove_socket(sock, nif, REMOVE_SOCKET_UNLOCKED) == true);
}

rwlock routing_table_lock;
cul::vector<inet4_route> routing_table;

netif *proto_family::route(sockaddr *from, sockaddr *to)
{
	sockaddr_in *in = (sockaddr_in *) from;

	/* If the source address specifies an interface, we need to use that one. */
	if(!is_bind_any(in->sin_addr.s_addr))
		return netif_get_from_addr(from, AF_INET);

	/* Else, we're searching through the routing table to find the best interface to use in order
	 * to reach our destination
	 */
	netif *best_if = nullptr;
	int lowest_metric = INT_MAX;
	auto dest = ((sockaddr_in *) to)->sin_addr.s_addr;

	rw_lock_read(&routing_table_lock);

	for(auto &r : routing_table)
	{
		/* Do a bitwise and between the destination address and the mask
		 * If the result = r.dest, we can use this interface.
		 */
#if 0
		printk("dest %x, mask %x, supposed dest %x\n", dest, r.mask, r.dest);
#endif
		if((dest & r.mask) != r.dest)
			continue;
#if 0
		printk("%s is good\n", r.nif->name);
		printk("is loopback set %u\n", r.nif->flags & NETIF_LOOPBACK);
#endif
	
		if(r.metric < lowest_metric)
		{
			best_if = r.nif;
			lowest_metric = r.metric;
		}
	}

	rw_unlock_read(&routing_table_lock);

	if(best_if)
	{
		in->sin_addr.s_addr = best_if->local_ip.sin_addr.s_addr;
	}

	return best_if;
}

bool add_route(inet4_route &route)
{
	rw_lock_write(&routing_table_lock);

	bool st = routing_table.push_back(route);

	rw_unlock_write(&routing_table_lock);

	return st;
}

static proto_family v4_protocol;

socket *create_socket(int type, int protocol)
{
	auto sock = choose_protocol_and_create(type, protocol);

	if(sock)
		sock->proto_domain = &v4_protocol;

	return sock;
}

}
}

bool inet_has_permission_for_port(in_port_t port)
{
	port = ntohs(port);

	if(port >= inet_min_unprivileged_port)
		return true;
	
	struct creds *c = creds_get();

	bool ret = c->euid == 0;
	
	creds_put(c);

	return ret;
}

/* Modifies *addr too */
bool inet_socket::validate_sockaddr_len_pair(sockaddr *addr, socklen_t len)
{
	bool v6 = domain == AF_INET6;

	if(!v6)
		return validate_sockaddr_len_pair_v4(reinterpret_cast<sockaddr_in*>(addr), len);
	else
		return validate_sockaddr_len_pair_v6(reinterpret_cast<sockaddr_in6*>(addr), len);
}

bool inet_socket::validate_sockaddr_len_pair_v4(sockaddr_in *addr, socklen_t len)
{
	if(len != sizeof(sockaddr_in))
		return false;

	return check_sockaddr_in(addr);
}

void inet_socket::unbind()
{
	bool is_inaddr_any = false;

	if(domain == AF_INET)
	{
		is_inaddr_any = ip::v4::is_bind_any(src_addr.in4.sin_addr.s_addr);
	}
	
	auto proto_fam = get_proto_fam();

	if(likely(is_inaddr_any))
	{
		auto list_start = netif_lock_and_get_list();

		list_for_every(list_start)
		{
			auto netif = container_of(l, struct netif, list_node);
			proto_fam->unbind_one(netif, this);
		}

		netif_unlock_list();
	}
	else
	{
		auto netif = netif_get_from_addr((sockaddr *) &src_addr, domain);
		proto_fam->unbind_one(netif, this);
	}
}

inet_socket::~inet_socket()
{
	unbind();
}

int inet_socket::setsockopt_inet(int level, int opt, const void *optval, socklen_t len)
{
	return -ENOPROTOOPT;
}

int inet_socket::getsockopt_inet(int level, int opt, void *optval, socklen_t *len)
{
	socklen_t length;
	if(copy_from_user(&length, len, sizeof(length)) < 0)
		return -EFAULT;

	/* Lessens the dupping of code */
	auto put_opt = [&](const auto &val) -> int
	{
		return put_option(val, length, len, optval);
	};

	switch(opt)
	{
		case IP_TTL:
			int ttl = 64;
			return put_opt(ttl);
	}

	return -ENOPROTOOPT;
}

size_t inet_socket::get_headers_len() const
{
	/* TODO: For all of inet_sockets code, we need to properly detect if we're
	 * an inet6 socket working as an inet4 one, or not.
	 */
	if(domain == AF_INET6)
		return sizeof(ip6_hdr);    /* TODO: Extensions */
	else
		return sizeof(ip_header);
}
