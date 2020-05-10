/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _ONYX_NET_IP_H
#define _ONYX_NET_IP_H

#include <stdint.h>

#include <onyx/net/netif.h>
#include <onyx/packetbuf.h>
#include <onyx/net/socket.h>
#include <onyx/net/proto_family.h>

#include <sys/socket.h>

#define IPV4_ICMP 1
#define IPV4_IGMP 2
#define IPV4_TCP 6
#define IPV4_UDP 17
#define IPV4_ENCAP 41
#define IPV4_OSPF 89
#define IPV4_SCTP 132

struct ip_header
{
	/* TODO: These bitfields are screwing up the structure's size, I think */
#if __BYTE_ORDER == __LITTLE_ENDIAN
	unsigned int ihl : 4;
	unsigned int version : 4;
#else
	unsigned int version : 4;
	unsigned int ihl : 4;
#endif
	uint8_t tos;
	uint16_t total_len;
	uint16_t identification;
	uint16_t frag_info;
	uint8_t ttl;
	uint8_t proto;
	uint16_t header_checksum;
	uint32_t source_ip;
	uint32_t dest_ip;
} __attribute__((packed));

union sockaddr_in_both
{
	sockaddr_in in4;
	sockaddr_in6 in6;
};

class inet_proto_family;

/* Forward declaration of ip::v4::proto_family for inet_socket friendship */
namespace ip
{

namespace v4
{
	class proto_family;
}

};

struct netif;
struct inet4_route
{
	in_addr_t dest;
	in_addr_t mask;
	netif *nif;
	int metric;
};

class inet_proto_family : public proto_family
{
public:
	virtual int bind(struct sockaddr *addr, socklen_t len, inet_socket *socket) = 0;
	virtual int bind_any(inet_socket *sock) = 0;
	virtual netif *route(sockaddr *from, sockaddr *to) = 0;
};

struct inet_socket : public socket
{
	/* in6 is able to hold sockaddr_in and sockaddr_in6, since it's bigger */
	sockaddr_in_both src_addr;
	sockaddr_in_both dest_addr;

	inet_socket() : socket{}, src_addr{}, dest_addr{} {}

	static uint32_t make_hash(inet_socket *& sock)
	{
		//size_t size_of_addr = sock->domain == AF_INET ? sizeof(sockaddr_in) : sizeof(sockaddr_in6);
		sockaddr_in *sin = (sockaddr_in *) &sock->src_addr.in4;
		auto hash = fnv_hash(&sock->proto, sizeof(int));
		hash = fnv_hash_cont(&sin->sin_port, sizeof(in_port_t), hash);
		//printk("Hashing proto %d port %u\n", sock->proto, sin->sin_port);

		return hash;
	}

	static uint32_t make_hash_from_id(const socket_id& id)
	{
		sockaddr_in *sin = (sockaddr_in *) &id.src_addr;
		auto hash = fnv_hash(&id.protocol, sizeof(id.protocol));
		hash = fnv_hash_cont(&sin->sin_port, sizeof(in_port_t), hash);
		//printk("Hashing proto %d port %u\n", id.protocol, sin->sin_port);

		return hash;
	}

	bool is_id(const socket_id& id, unsigned int flags) const
	{
		//size_t size_of_addr = domain == AF_INET ? sizeof(sockaddr_in) : sizeof(sockaddr_in6);
		sockaddr_in *this_sin = (sockaddr_in *) &src_addr;
		sockaddr_in *other_sin = (sockaddr_in *) &id.src_addr;

		return proto == id.protocol && this_sin->sin_port == other_sin->sin_port &&
		       (!(flags & GET_SOCKET_DSTADDR_VALID) || !memcmp(&dest_addr, &id.dst_addr, sizeof(sockaddr_in)));
	}

	inet_proto_family *get_proto_fam()
	{
		return static_cast<inet_proto_family *>(proto_domain);
	}

private:
	friend class ip::v4::proto_family;
	bool validate_sockaddr_len_pair_v4(sockaddr_in *addr, socklen_t len);
	bool validate_sockaddr_len_pair_v6(sockaddr_in6 *addr, socklen_t len);
protected:
	/* Modifies *addr too */
	bool validate_sockaddr_len_pair(sockaddr *addr, socklen_t len);
};

#define IPV4_MIN_HEADER_LEN			20

#define IPV4_FRAG_INFO_DONT_FRAGMENT	0x4000
#define IPV4_FRAG_INFO_MORE_FRAGMENTS	0x2000

#define IPV4_FRAG_INFO_FLAGS(x)		(x & 0x7)
#define IPV4_MAKE_FRAGOFF(x)		(x << 3)
#define IPV4_GET_FRAGOFF(x)			(x >> 2)

static inline uint16_t __ipsum_unfolded(void *addr, size_t bytes, uint16_t init_count)
{
	uint32_t sum = init_count;
	uint32_t ret = 0;
	uint16_t __attribute__((may_alias)) *ptr = (uint16_t __attribute__((may_alias)) *) addr;
	size_t words = bytes / 2;
	for(size_t i = 0; i < words; i++)
	{
		sum += ptr[i];
	}

	ret = sum & 0xFFFF;
	uint32_t carry = sum - ret;
	while(carry)
	{
		ret += carry;
		carry = ret >> 16;
		ret &= 0xFFFF;
	}

	return ret;
}

static inline uint16_t ipsum_unfolded(void *addr, size_t bytes)
{
	return __ipsum_unfolded(addr, bytes, 0);
}

static inline uint16_t ipsum_fold(uint16_t s)
{
	return ~s;
}

static inline uint16_t ipsum(void *addr, size_t bytes)
{
	return ipsum_fold(ipsum_unfolded(addr, bytes));
}

namespace ip
{

namespace v4
{

class proto_family : public inet_proto_family
{
private:
	int bind_one(sockaddr_in *in, netif *nif, inet_socket *sock);
public:
	virtual int bind(sockaddr *addr, socklen_t len, inet_socket *socket) override;
	virtual int bind_any(inet_socket *sock) override;
	virtual netif *route(sockaddr *from, sockaddr *to) override;
};

int send_packet(uint32_t senderip, uint32_t destip, unsigned int type,
                     struct packetbuf_info *buf, struct netif *netif);

socket *create_socket(int type, int protocol);

void handle_packet(struct ip_header *header, size_t size, struct netif *netif);

bool add_route(inet4_route &route);

};

};

extern struct packetbuf_proto __ipv4_pbf;

inline void ipv4_to_sockaddr(in_addr_t addr, in_port_t port, sockaddr_in &in)
{
	in.sin_addr.s_addr = addr;
	in.sin_family = AF_INET;
	in.sin_port = port;
	memset(&in.sin_zero, 0, sizeof(in.sin_zero));
}

inline bool check_sockaddr_in(sockaddr_in *in)
{
	if(in->sin_family != AF_INET)
		return false;

	memset(&in->sin_zero, 0, sizeof(in->sin_zero));
	return true;
}

static inline struct packetbuf_proto *ipv4_get_packetbuf(void)
{
	return &__ipv4_pbf;
}

/* This routine also handles broadcast addresses and all complexity envolved with ip addresses */
template <typename T>
inline T *inet_resolve_socket(in_addr_t src, in_port_t port_src, in_port_t port_dst,
                              int proto, netif *nif, bool ign_dst = false)
{
	struct sockaddr_in socket_dst;
	struct sockaddr_in socket_src;
	struct sockaddr_in socket_dst_broadcast;
	unsigned int flags = !ign_dst ? GET_SOCKET_DSTADDR_VALID : 0;
	ipv4_to_sockaddr(INADDR_BROADCAST, port_src, socket_dst_broadcast);
	ipv4_to_sockaddr(src, port_src, socket_dst);
	ipv4_to_sockaddr(nif->local_ip.sin_addr.s_addr, port_dst, socket_src);

	const socket_id id(proto, sa_generic(socket_src), sa_generic(socket_dst));
	const socket_id other_possible_id(proto, sa_generic(socket_src), sa_generic(socket_dst_broadcast));

	auto socket = netif_get_socket(id, nif, flags);

	if(!socket)
		socket = netif_get_socket(other_possible_id, nif, flags);
	
	return static_cast<T *>(socket);
}

/* Ports under 1024 are privileged; they can only bound to by root. */
static constexpr uint16_t inet_min_unprivileged_port = 1024;

/* 'port' is a big-endian(or network order) variable */
bool inet_has_permission_for_port(in_port_t port);

#endif
