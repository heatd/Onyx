/*
* Copyright (c) 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <time.h>
#include <stdarg.h>
#include <string.h>

#include <sys/syscall.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/ioctl.h>

#include <dhcp.h>

#define DHCP_MIN_OPT_OFFSET	4

char *program_name;
void error(char *msg, ...)
{
	va_list ap;
	va_start(ap, msg);
	fprintf(stderr, "%s: error: ", program_name);
	vfprintf(stderr, msg, ap);
	va_end(ap);
}

void errorx(char *msg, ...)
{
	va_list ap;
	va_start(ap, msg);
	fprintf(stderr, "%s: error: ", program_name);
	vfprintf(stderr, msg, ap);
	va_end(ap);
	exit(1);
}

uint32_t dhcp_get_random_xid(void)
{
	return (uint32_t) random();
}

void init_entropy(void)
{
	unsigned int seed = 0;
	if(syscall(SYS_getrandom, &seed, sizeof(seed), 0) < 0)
		errorx("Couldn't gather entropy: %s\n", strerror(errno));
	struct timespec t = {0};
	clock_gettime(CLOCK_REALTIME, &t);
	srandom(seed ^ t.tv_nsec | t.tv_sec);
}

off_t dhcp_add_option(dhcp_packet_t *pkt, off_t off, unsigned char len,
		      const void *buf, size_t size_buf, unsigned char opt)
{
	pkt->options[off++] = opt;
	pkt->options[off++] = len;
	memcpy(&pkt->options[off], buf, size_buf);
	return off + size_buf;
}

void dhcp_close_options(dhcp_packet_t *pkt, off_t off)
{
	/* Add the needed padding */
	memset(&pkt->options[off], 0, 3);
	off += 3;
	pkt->options[off] = DHO_END;
}

int dhcp_decode_boot_packet(int fd, dhcp_packet_t *packet)
{
	uint32_t router_ip;
	uint32_t assigned_ip;
	uint32_t subnet_mask;
	uint32_t dns_server;
	uint32_t lease_time;

	uint32_t our_ip = htonl(packet->yiaddr);
	//printf("Assigned IP: %x\n", our_ip);
	unsigned char *opt = (unsigned char *) &packet->options;

	if(memcmp(opt, DHCP_OPTIONS_COOKIE, 4) == 1)
	{
		printf("dhcpcd: Bad cookie\n");
		return -1;
	}

	opt += 4;
	while(*opt != DHO_END)
	{
		switch(*opt)
		{
			case DHO_ROUTERS:
			{
				opt += 2;
				router_ip = ntohl(*(uint32_t *) opt);
				//printf("Router ip: %x\n", router_ip);
				opt += 4;
				break;
			}
			case DHO_SUBNET_MASK:
			{
				opt += 2;
				subnet_mask = ntohl(*(uint32_t *) opt);
				//printf("Subnet mask: %x\n", router_ip);
				opt += 4;
				break;
			}
			case DHO_DOMAIN_NAME_SERVERS:
			{
				opt += 2;
				dns_server = ntohl(*(uint32_t *) opt);
				//printf("DNS server: %x\n", dns_server);
				opt += 4;
				break;
			}
			case DHO_DHCP_LEASE_TIME:
			{
				opt += 2;
				lease_time = ntohl(*(uint32_t *) opt);
				//printf("DHCP lease time: %us\n", lease_time);
				opt += 4;
				break;
			}
			default:
			{
				opt++;
				unsigned char length = *opt;
				opt = opt + length + 1;
				break;
			}
		}
	}
	
	struct if_config_inet cfg;
	cfg.address.s_addr = our_ip;
	cfg.subnet.s_addr = subnet_mask;
	cfg.router.s_addr = router_ip;
	if(ioctl(fd, SIOSETINET4, &cfg) < 0)
	{
		perror("SIOSETINET4");
		return -1;
	}

	return 0;
}

int dhcp_setup_netif(int fd, int sock)
{
	unsigned char mac[6];
	if(ioctl(fd, SIOGETMAC, &mac) < 0)
	{
		errorx("ioctl: Could not get the local mac address: %s\n", strerror(errno));
	}

	dhcp_packet_t *boot_packet = malloc(sizeof(dhcp_packet_t));
	if(!boot_packet)
	{
		errorx("%s: %s\n", "Error allocating the boot packet", 
			strerror(errno));
	}
	
	memset(boot_packet, 0, sizeof(dhcp_packet_t));
	memcpy(&boot_packet->chaddr, &mac, 6);
	boot_packet->xid = dhcp_get_random_xid();
	boot_packet->hlen = 6;
	boot_packet->htype = HTYPE_ETHER;
	boot_packet->op = BOOTREQUEST;
	boot_packet->flags = 0x8000;

	off_t off = DHCP_MIN_OPT_OFFSET;
	memcpy(&boot_packet->options, DHCP_OPTIONS_COOKIE, 4);

	unsigned char message_type = DHCPDISCOVER;
	off = dhcp_add_option(boot_packet, off, 1, &message_type,
			      sizeof(message_type), DHO_DHCP_MESSAGE_TYPE);
	unsigned char opts[3] = {DHO_SUBNET_MASK, DHO_ROUTERS,
				 DHO_DOMAIN_NAME_SERVERS};
	off = dhcp_add_option(boot_packet, off, 3, &opts, sizeof(opts),
			      DHO_DHCP_PARAMETER_REQUEST_LIST);
	dhcp_close_options(boot_packet, off);

	if(send(sock, boot_packet, sizeof(dhcp_packet_t), 0) < 0)
	{
		error("send: Error sending the boot packet: %s\n",
		      strerror(errno));
		return -1;
	}

	//printf("Sent packet\n");

	memset(boot_packet, 0, sizeof(dhcp_packet_t));
	if(recv(sock, boot_packet, sizeof(dhcp_packet_t), 0) < 0)
	{
		error("recv: Error recieving the response packet: %s\n",
		      strerror(errno));
		return -1;
	}

	//printf("Decoding boot packet\n");
	dhcp_decode_boot_packet(fd, boot_packet);

}

int main(int argc, char **argv, char **envp)
{
	program_name = argv[0];
	int logfd = open("/dev/null", O_RDWR);
	if(logfd < 0)
	{
		perror("could not create logfd");
		return 0;
	}

#if 0
	dup2(logfd, 0);
	dup2(logfd, 1);
	dup2(logfd, 2);
#endif

	close(logfd);

	printf("%s: Daemon initialized\n", argv[0]);

	int fd = open("/dev/eth0", O_RDWR);
	if(fd < 0)
	{
		perror("/dev/eth0");
		return 1;
	}

	int sock = socket(AF_INET, SOCK_DGRAM, 0);
	if(sock < 0)
	{
		perror("Error creating a socket");
		close(fd);
		return 1;
	}

	struct sockaddr_in sockaddr = {0};
	sockaddr.sin_port = htons(68);
	if(bind(sock, (const struct sockaddr *) &sockaddr, sizeof(struct sockaddr)) < 0)
	{
		perror("dhcpcd: bind");
		return 1;
	}

	sockaddr.sin_port = htons(67);
	sockaddr.sin_addr.s_addr = 0xFFFFFFFF;
	
	if(connect(sock, (const struct sockaddr *) &sockaddr, sizeof(struct sockaddr)) < 0)
	{
		perror("dhcpcd: connect");
		return 1;
	}

	/* After doing some work, initialize entropy */
	init_entropy();

	dhcp_setup_netif(fd, sock);
	while(1)
		sleep(100000);
	return 0;
}
