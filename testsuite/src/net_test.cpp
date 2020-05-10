/*
 * Copyright (c) 2020 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
*/
#include <unistd.h>
#include <stdio.h>
#include <byteswap.h>

#include <sys/socket.h>
#include <netinet/in.h>

#include <test/libtest.h>

bool net_loopback_test()
{
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	if(fd < 0)
	{
		perror("socket");
		return false;
	}

	int clientfd = socket(AF_INET, SOCK_DGRAM, 0);
	if(clientfd < 0)
	{
		close(fd);
		perror("socket");
		return false;
	}

	struct sockaddr_in in{};
	in.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	in.sin_family = AF_INET;
	in.sin_port = htons(32);

	char c = 'x';
	char recved = 0;

	if(bind(fd, (sockaddr *) &in, sizeof(sockaddr_in)) < 0)
	{
		perror("bind");
		goto close_everything;
	}

	if(connect(clientfd, (sockaddr *) &in, sizeof(sockaddr_in)) < 0)
	{
		perror("connect");
		goto close_everything;
	}

	if(send(clientfd, &c, 1, 0) < 0)
	{
		perror("send");
		goto close_everything;
	}

	if(recv(fd, &recved, 1, 0) < 0)
	{
		perror("recv");
		goto close_everything;
	}

	close(fd);
	close(clientfd);

	return recved == c;
close_everything:
	close(fd);
	close(clientfd);
	return false;
}

DECLARE_TEST(net_loopback_test, 2);

