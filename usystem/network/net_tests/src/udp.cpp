/*
* Copyright (c) 2020 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#include <gtest/gtest.h>
#include <limits>

#include <sys/socket.h>

#include <netinet/ip.h>
#include <arpa/inet.h>

TEST(Udp, CorkWorks)
{
	int sock = socket(AF_INET, SOCK_DGRAM, 0);

	ASSERT_NE(sock, -1);

	sockaddr_in sa = {};
	sa.sin_addr.s_addr = INADDR_ANY;
	sa.sin_port = htons(1066);
	sa.sin_family = AF_INET;

	ASSERT_NE(bind(sock, (const sockaddr *) &sa, sizeof(sa)), -1);

	void *ptr = new char[std::numeric_limits<uint16_t>::max()];

	iovec v;
	v.iov_base = ptr;
	v.iov_len = std::numeric_limits<uint16_t>::max();

	msghdr msg;
	msg.msg_control = nullptr;
	msg.msg_controllen = 0;
	msg.msg_flags = 0;
	msg.msg_iov = &v;
	msg.msg_iovlen = 1;

	sa.sin_addr.s_addr = inet_addr("104.196.199.218");
	msg.msg_name = &sa;
	msg.msg_namelen = sizeof(sa);

	for(int i = 0; i < 80; i++)
	{
		int flags = MSG_MORE;
		if(i == 79)
			flags &= ~MSG_MORE;
		
		int st = sendmsg(sock, &msg, flags);
		if(st < 0)
		{
			perror("sendmsg");
			ASSERT_NE(st, -1);
		}
	}
}
