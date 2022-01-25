/*
 * Copyright (c) 2020 - 2021 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

/* Implementation of the ping command for Onyx */

#include <cstdint>
#include <stdio.h>
#include <unistd.h>
#include <cstdlib>
#include <cstring>
#include <errno.h>

#include <getopt.h>
#include <netdb.h>
#include <arpa/inet.h>

#include <chrono>
#include <random>
#include <memory>
#include <tuple>

#include <sys/socket.h>

#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>

#include <onyx/public/icmp.h>

const struct option long_options[] =
{ 
	{"help", 0, nullptr, 'h'},
	{"version", 0, nullptr, 'v'},
	{"flood", 0, nullptr, 'f'},
	{}
};

void show_help(int flag)
{
	/* Return 1 if it was an invalid flag. */
	int ret = flag == '?';

	printf("Usage:\n   ping [options] <destination>\nOptions:\n"
	       "   -h/--help     print help and exit\n"
		   "   -v            print version and exit\n"
		   "   -c <count>    number of pings to issue\n"
		   "   -f/--flood    flood: do not delay pings\n"
		   "   -i <interval> interval, in seconds, between pings\n"
		   "   -6            use IPv6\n"
		   "   -4            use IPv4\n");
	
	std::exit(ret);
}

void show_version()
{
	printf("Onyx ping from Onyx utils 14082020\n");
	std::exit(0);
}

unsigned int count = 0;
bool do_flood = false;
double interval = 1.0;
int force_family = AF_UNSPEC;
size_t payload_size = 56;

int setup_icmp_socket(addrinfo *info, bool isv6)
{
	int fd = socket(info->ai_family, SOCK_DGRAM, isv6 ? IPPROTO_ICMPV6 : IPPROTO_ICMP);
	if(fd < 0)
	{
		perror("ping: Could not create socket");
		return -1;
	}

	if(connect(fd, info->ai_addr, info->ai_addrlen) < 0)
	{
		perror("ping: Could not connect socket");
		return -1;
	}

	icmp_filter filt;
	filt.code = 0;
	filt.type = isv6 ? ICMP6_ECHO_REPLY : ICMP_ECHOREPLY;

	if(setsockopt(fd, isv6 ? SOL_ICMPV6 : SOL_ICMP, ICMP_ADD_FILTER, &filt, sizeof(filt)) < 0)
	{
		perror("ping: Error adding filter");
		return -1;
	}

	return fd;
}

std::pair<std::unique_ptr<unsigned char []>, size_t> icmp_header(bool v6, std::uint16_t id, std::uint16_t seq)
{
	auto header_size = v6 ? sizeof(icmp6_hdr) : sizeof(icmphdr);
	std::unique_ptr<unsigned char[]> ptr{new unsigned char[header_size]};
	if (v6)
	{
		icmp6_hdr *hdr = (icmp6_hdr *) ptr.get();
		hdr->icmp6_type = ICMP6_ECHO_REQUEST;
		hdr->icmp6_code = 0;
		hdr->icmp6_dataun.icmp6_un_data16[0] = id;
		hdr->icmp6_dataun.icmp6_un_data16[1] = htons(seq);
	}
	else
	{
		icmphdr *hdr = (icmphdr *) ptr.get();
		hdr->type = ICMP_ECHO;
		hdr->code = 0;
		hdr->un.echo.id = id;
		hdr->un.echo.sequence = htons(seq);
	}

	return std::make_pair(std::move(ptr), header_size);
}

std::unique_ptr<unsigned char[]> create_icmp_payload(std::mt19937 &rng)
{
	std::unique_ptr<unsigned char[]> ptr{new unsigned char[payload_size]};

	for (size_t i = 0; i < payload_size; i++)
	{
		ptr[i] = (std::uint8_t) rng();
	}

	return ptr;
}

enum icmp_pkt_check_res
{
	ICMP_PKT_CHECK_VALID = 0,
	ICMP_PKT_CHECK_NOT_OURS = 1,
	ICMP_PKT_CHECK_BAD_PACKET = -1
};

icmp_pkt_check_res icmp_check_response(unsigned char *header, unsigned char *payload, std::uint16_t seq,
                                             size_t size,
                                             std::uint16_t id, unsigned char *desired_payload, bool v6)
{
	if (v6)
	{
		icmp6_hdr *hdr = (icmp6_hdr *) header;
		if (hdr->icmp6_dataun.icmp6_un_data16[0] != id)
			return ICMP_PKT_CHECK_NOT_OURS;
		
		if (hdr->icmp6_dataun.icmp6_un_data16[1] != htons(seq))
			return ICMP_PKT_CHECK_BAD_PACKET;
	}
	else
	{
		icmphdr *hdr = (icmphdr *) header;
		if (hdr->un.echo.id != id)
			return ICMP_PKT_CHECK_NOT_OURS;
		
		if (hdr->un.echo.sequence != htons(seq))
			return ICMP_PKT_CHECK_BAD_PACKET;
	}

	if (size - sizeof(icmphdr) != payload_size)
		return ICMP_PKT_CHECK_BAD_PACKET;

	for (size_t i = 0; i < payload_size; i++)
	{
		if (payload[i] != desired_payload[i])
			return ICMP_PKT_CHECK_BAD_PACKET;
	}

	return ICMP_PKT_CHECK_VALID;
}

int do_ping(const char *dst)
{
	char text_address[INET6_ADDRSTRLEN];
	addrinfo *result;
	addrinfo hints;
	std::memset(&hints, 0, sizeof(hints));

	hints.ai_family = force_family;
	
	int st = getaddrinfo(dst, "0", &hints, &result);

	if(st != 0)
	{
		fprintf(stderr, "ping: getaddrinfo: %s\n", gai_strerror(st));
		return 1;
	}

	bool isv6 = result->ai_family == AF_INET6; 

	int fd = setup_icmp_socket(result, isv6);

	if (fd < 0)
		return 1;

	const void *ntop_addr = nullptr;

	if (isv6)
	{
		ntop_addr = &((sockaddr_in6 *) result->ai_addr)->sin6_addr;
	}
	else
	{
		ntop_addr = &((sockaddr_in *) result->ai_addr)->sin_addr;
	}

	if (!inet_ntop(result->ai_family, ntop_addr, text_address, sizeof(text_address)))
	{
		perror("inet_ntop");
		return 1;
	}

	bool count_valid = count != 0;

	std::random_device dev;
	std::mt19937 rng(dev());
	std::uniform_int_distribution<std::mt19937::result_type> dist(0, UINT16_MAX);

	std::uint16_t id = (std::uint16_t) dist(rng);

	std::uint16_t seq = 0;
	printf("PING %s (%s)\n", dst, text_address);

	auto payload = create_icmp_payload(rng);
	auto original_payload = new unsigned char[payload_size];

	std::memcpy(original_payload, payload.get(), payload_size);

	ssize_t last_read = 0;

	/* TODO: Support sending larger payloads */

	while(!count_valid || count-- != 0)
	{
		auto [header, header_len] = icmp_header(isv6, id, seq);

		auto t0 = std::chrono::high_resolution_clock::now();

		struct iovec iov[2];
		iov[0].iov_base = header.get();
		iov[0].iov_len = header_len;

		iov[1].iov_base = payload.get();
		iov[1].iov_len = payload_size;

		struct msghdr msg;
		msg.msg_name = nullptr;
		msg.msg_namelen = 0;
		msg.msg_control = nullptr;
		msg.msg_controllen = 0;
		msg.msg_flags = 0;
		msg.msg_iov = iov;
		msg.msg_iovlen = 2;
		if(sendmsg(fd, &msg, 0) < 0)
		{
			perror("ping: Error sending ICMP packet");
			return 1;
		}

		/* TODO: Timeout? */
		while(true)
		{
			ssize_t st = recvmsg(fd, &msg, MSG_TRUNC);

			if (st < 0)
			{
				perror("recvmsg");
				return 1;
			}

			last_read = st;

			auto res = icmp_check_response(header.get(), payload.get(), seq, (size_t) st, id, original_payload, isv6);

			if (res == ICMP_PKT_CHECK_NOT_OURS)
				continue;
			
			if (res == ICMP_PKT_CHECK_BAD_PACKET)
			{
				printf("ICMP: Bad packet\n");
				// Restore a possible payload change
				std::memcpy(payload.get(), original_payload, payload_size);
			}

			break;
		}

		auto t1 = std::chrono::high_resolution_clock::now();

		auto delta = std::chrono::duration_cast<std::chrono::duration<double, std::milli>>(t1 - t0);

		printf("%lu bytes from %s: icmp_seq=%u time=%.2f ms\n", last_read, dst, seq, delta.count());

		seq++;

		if((!count_valid || count != 0) && !do_flood)
		{
			usleep(interval * 1000000);
		}
	}

	return 0;
}

int main(int argc, char **argv, char **envp)
{
	int indexptr = 0;
	int flag = 0;
	while((flag = getopt_long(argc, argv, "vfhc:i:64", long_options, &indexptr)) != -1)
	{
		switch(flag)
		{
			case '?':
			case 'h':
				show_help(flag);
				break;
			case 'v':
				show_version();
				break;
			case 'c':
				errno = 0;
				count = std::strtoul(optarg, nullptr, 10);

				if(errno == ERANGE || count == 0)
				{
					printf("ping: Count number out of range [1, UINT_MAX]\n");
					exit(1);
				}

				break;

			case 'f':
				do_flood = true;
				break;
			
			case 'i':
				errno = 0;
				interval = std::strtod(optarg, nullptr);

				if(errno == ERANGE || count == 0)
				{
					printf("ping: Interval out of range\n");
					exit(1);
				}
				break;
			
			case '6':
				force_family = AF_INET6;
				break;
			
			case '4':
				force_family = AF_INET;
				break;
		}
	}

	if(optind == argc)
	{
		show_help('?');
	}

	const char *dst = argv[optind];

	return do_ping(dst);
}
