/*
* Copyright (c) 2016-2020 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _ONYX_NET_IP_H
#define _ONYX_NET_IP_H

#include <stdint.h>

#include <onyx/net/inet_sock_addr.h>
#include <onyx/net/netif.h>
#include <onyx/packetbuf.h>
#include <onyx/net/socket.h>
#include <onyx/net/proto_family.h>
#include <onyx/net/ipv6.h>

#include <sys/socket.h>
#include <netinet/ip6.h>

#define IPV4_ICMP 1
#define IPV4_IGMP 2
#define IPV4_TCP 6
#define IPV4_UDP 17
#define IPV4_ENCAP 41
#define IPV4_OSPF 89
#define IPV4_SCTP 132

struct ip_header
{
	/* TODO: These bitfields are screwing up the structure's size,
	 * although I think it's an intellisense problem. The problem doesn't seem to arise when compiling the code.
	 */
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

static constexpr uint16_t ip_header_length(const ip_header *hdr)
{
	return hdr->ihl << 2;
}

union sockaddr_in_both
{
	sockaddr_in in4;
	sockaddr_in6 in6;
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
	virtual netif *route(inet_sock_address& from, const inet_sock_address &to, int domain) = 0;
	virtual void unbind_one(netif *nif, inet_socket *sock) = 0;
};

#define IPV4_MIN_HEADER_LEN			20

#define IPV4_FRAG_INFO_DONT_FRAGMENT	0x4000
#define IPV4_FRAG_INFO_MORE_FRAGMENTS	0x2000

#define IPV4_FRAG_INFO_FLAGS(x)		(x & 0x7)
#define IPV4_MAKE_FRAGOFF(x)		(x << 3)
#define IPV4_GET_FRAGOFF(x)			(x >> 2)


typedef uint32_t __attribute__((may_alias)) may_alias_uint32_t;
typedef uint64_t __attribute__((may_alias)) may_alias_uint64_t;
typedef uint16_t __attribute__((may_alias)) may_alias_uint16_t;
typedef uint8_t __attribute__((may_alias)) may_alias_uint8_t;

#define IS_BUFFER_ALIGNED_TO(buf, boundary)  (((unsigned long) buf) & boundary)

#ifdef __x86_64__

#define ADD_CARRY_64_BYTES(buf, result)  \
__asm__ __volatile__("addq 0*8(%[buf]), %[res]\n\t" \
					 "adcq 1*8(%[buf]), %[res]\n\t" \
					 "adcq 2*8(%[buf]), %[res]\n\t" \
					 "adcq 3*8(%[buf]), %[res]\n\t" \
					 "adcq 4*8(%[buf]), %[res]\n\t" \
					 "adcq 5*8(%[buf]), %[res]\n\t" \
					 "adcq 6*8(%[buf]), %[res]\n\t" \
					 "adcq 7*8(%[buf]), %[res]\n\t" \
					 "adc $0, %[res]" : [res] "=r"(result) \
					 : [buf] "r"(buf), "[res]" "r"(result))

#define ADD_CARRY_64BIT(buf, result) \
__asm__ __volatile__("addq (%1), %0\n\t" \
					 "adc $0, %0\n\t" : "=r"(result) : "r"(buf), "0" "r"(result))

static inline uint16_t fold32_to_16(uint32_t a) 
{
	uint16_t b = a >> 16; 
	__asm__ __volatile__("addw %w2, %w0\n\t"
                         "adcw $0, %w0\n" 
	                     : "=r"(b)
						 : "0"(b), "r"(a));
	return b;
}

static inline uint32_t addcarry32(uint32_t a, uint32_t b)
{
	__asm__ __volatile__("addl %2, %0\n\t"
                         "adcl $0, %0"
                         : "=r"(a)
                         : "0"(a), "rm"(b));
	return a;
}

#endif

using inetsum_t = uint32_t;

inetsum_t do_checksum(const uint8_t *buf, size_t len);

static inline inetsum_t __ipsum_unfolded(const void *addr, size_t bytes, inetsum_t starting_csum)
{
	return addcarry32(starting_csum, do_checksum((const uint8_t *) addr, bytes));
}

static inline inetsum_t ipsum_unfolded(const void *addr, size_t length)
{
	return do_checksum((const uint8_t *) addr, length);
}

static inline uint16_t ipsum_fold(inetsum_t cs)
{
	return ~fold32_to_16(cs);
}

static inline uint16_t ipsum(const void *addr, size_t bytes)
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
	int bind(sockaddr *addr, socklen_t len, inet_socket *socket) override;
	int bind_any(inet_socket *sock) override;
	netif *route(inet_sock_address& from, const inet_sock_address &to, int domain) override;
	void unbind_one(netif *nif, inet_socket *sock) override;
};

int send_packet(uint32_t senderip, uint32_t destip, unsigned int type,
                     packetbuf *buf, struct netif *netif);

socket *create_socket(int type, int protocol);

void handle_packet(struct ip_header *header, size_t size, struct netif *netif);

bool add_route(inet4_route &route);

inline constexpr cul::pair<inet_sock_address, int> sockaddr4_to_isa(const sockaddr_in* sa)
{
	return {inet_sock_address{*sa}, AF_INET};
}

};

};

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

/* This routine also handles broadcast addresses and all complexity envolved with ip addresses */
template <typename T>
inline T *inet_resolve_socket(in_addr_t src, in_port_t port_src, in_port_t port_dst,
                              int proto, netif *nif, bool ign_dst = false)
{
	in_addr __src;
	__src.s_addr = src;
	auto flags = (!ign_dst ? GET_SOCKET_DSTADDR_VALID : 0);

	const inet_sock_address socket_dst{__src, port_src};
	const inet_sock_address socket_src{nif->local_ip.sin_addr, port_dst};

	const socket_id id(proto, AF_INET, socket_src, socket_dst);

	auto socket = netif_get_socket(id, nif, flags);
	
	return static_cast<T *>(socket);
}

/* Ports under 1024 are privileged; they can only bound to by root. */
static constexpr uint16_t inet_min_unprivileged_port = 1024;

/* 'port' is a big-endian(or network order) variable */
bool inet_has_permission_for_port(in_port_t port);

/**
 * @brief Converts a plain, generic sockaddr into an internal representation, and handles IPv6 cleanly.
 * 
 * @param sa the socket address 
 * @return cul::pair<inet_sock_address, int> a pair representing the socket address and the domain 
 */
inline cul::pair<inet_sock_address, int> sockaddr_to_isa(const sockaddr* sa)
{
	if(sa->sa_family == AF_INET)
		return ip::v4::sockaddr4_to_isa(reinterpret_cast<const sockaddr_in *>(sa));
	else
		return ip::v6::sockaddr6_to_isa(reinterpret_cast<const sockaddr_in6 *>(sa));
}

#endif
