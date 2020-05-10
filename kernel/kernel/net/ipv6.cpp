/*
* Copyright (c) 2020 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#include <onyx/net/ip.h>

bool inet_socket::validate_sockaddr_len_pair_v6(sockaddr_in6 *addr, socklen_t len)
{
	if(len != sizeof(sockaddr_in6))
		return false;

	return addr->sin6_family == AF_INET6;
}
