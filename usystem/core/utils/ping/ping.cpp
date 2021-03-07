/*
* Copyright (c) 2020 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

/* Implementation of the ping command for Onyx */

#include <cstdint>
#include <stdio.h>
#include <unistd.h>
#include <cstdlib>
#include <errno.h>

#include <getopt.h>
#include <netdb.h>
#include <arpa/inet.h>

#include <chrono>

#include <random>

#include <sys/socket.h>

#include <netinet/ip_icmp.h>

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
		   "   -i <interval> interval, in seconds, between pings\n");
	
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

int do_ping(const char *dst)
{
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
	if(fd < 0)
	{
		perror("ping: Could not create socket");
		return 1;
	}

	/* TODO: IPv6 ping */
	hostent *ent = gethostbyname2(dst, AF_INET);
	if(!ent)
	{
		perror("ping: Could not resolve address");
		return 1;
	}

	in_addr **address_list = (in_addr **) ent->h_addr_list;
    sockaddr_in addr;
	addr.sin_family = AF_INET; 
    addr.sin_addr.s_addr = address_list[0]->s_addr;
    addr.sin_port = 0;

	if(connect(fd, (sockaddr *) &addr, sizeof(addr)) < 0)
	{
		perror("ping: Could not connect socket");
		return 1;
	}

	icmp_filter filt;
	filt.code = 0;
	filt.type = ICMP_ECHOREPLY;

	if(setsockopt(fd, SOL_ICMP, ICMP_ADD_FILTER, &filt, sizeof(filt)) < 0)
	{
		perror("ping: Error adding filter");
		return 1;
	}

	bool count_valid = count != 0;

	std::random_device dev;
	std::mt19937 rng(dev());
	std::uniform_int_distribution<std::mt19937::result_type> dist(0, UINT16_MAX);

	std::uint16_t id = (std::uint16_t) dist(rng);

	std::uint16_t seq = 0;
	printf("PING %s (%s)\n", dst, inet_ntoa(addr.sin_addr));

	/* TODO: Support sending larger payloads */

	while(!count_valid || count-- != 0)
	{
		icmphdr hdr;
		hdr.un.echo.id = id;
		hdr.un.echo.sequence = htons(seq);
		hdr.type = ICMP_ECHO;
		hdr.code = 0;
		hdr.checksum = 0;

		auto t0 = std::chrono::high_resolution_clock::now();

		if(send(fd, &hdr, sizeof(hdr), 0) < 0)
		{
			perror("ping: Error sending ICMP packet");
			return 1;
		}

		/* TODO: Timeout? */
		while(true)
		{
			if(recv(fd, &hdr, sizeof(hdr), 0) < 0)
			{
				perror("recv");
				return 1;
			}

			if(hdr.un.echo.id == id && hdr.un.echo.sequence == htons(seq))
				break;
		}

		auto t1 = std::chrono::high_resolution_clock::now();

		auto delta = std::chrono::duration_cast<std::chrono::duration<double, std::milli>>(t1 - t0);

		printf("%lu bytes from %s: icmp_seq=%u time=%.2f ms\n", sizeof(hdr), dst, seq, delta.count());

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
	while((flag = getopt_long(argc, argv, "vfhc:i:", long_options, &indexptr)) != -1)
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
		}
	}

	if(optind == argc)
	{
		show_help('?');
	}

	const char *dst = argv[optind];

	return do_ping(dst);
}
