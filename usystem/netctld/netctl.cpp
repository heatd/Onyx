/*
* Copyright (c) 2020 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <fcntl.h>
#include <string.h>

#include <onyx/public/netkernel.h>

#include <sys/socket.h>

#include "dhcpcd.hpp"

int main(int argc, char **argv, char **envp)
{
	int logfd = open("/dev/null", O_RDWR);
	if(logfd < 0)
	{
		perror("could not create logfd");
		return 1;
	}

#if 0
	dup2(logfd, 0);
	dup2(logfd, 1);
	dup2(logfd, 2);
#endif

	close(logfd);

	dhcpcd::nkfd = socket(AF_NETKERNEL, SOCK_DGRAM, 0);
	if(dhcpcd::nkfd < 0)
	{
		perror("nksocket");
		return 1;
	}

	dhcpcd::rtfd = socket(AF_NETKERNEL, SOCK_DGRAM, 0);
	if(dhcpcd::rtfd < 0)
	{
		perror("nksocket");
		return 1;
	}

	sockaddr_nk nksa;
	nksa.nk_family = AF_NETKERNEL;
	strcpy(nksa.path, "ipv4.rt");
	if(connect(dhcpcd::rtfd, (const sockaddr *) &nksa, sizeof(nksa)) < 0)
	{
		perror("nkconnect");
		return 1;
	}

	printf("%s: Daemon initialized\n", argv[0]);

	/* TODO: Discover NICs in /dev (maybe using netlink? or sysfs) */
	
	std::string name{"/dev/eth0"};
	dhcpcd::init_entropy();

	dhcpcd::create_instance(name);

	while(1)
		sleep(100000);
	return 0;
}
