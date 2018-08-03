/*
* Copyright (c) 2018 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#include <algorithm>
#include <assert.h>
#include <stdio.h>
#include <iostream>
#include <stdlib.h>
#include <string.h>
#include <err.h>
#include <fcntl.h>
#include <unistd.h>
#include <server.h>
#include <display.h>
#include <window.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#define SERVER_SOCKET_PATH	"\0wserver.message_queue"

Server::Server(std::shared_ptr<Display> display) : display(display),
	window_list()
{
	socket_fd = socket(AF_UNIX, SOCK_DGRAM, 0);

	if(socket_fd < 0)
	{
		throw std::runtime_error("socket failed");
	}

	struct sockaddr_un addr;
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, SERVER_SOCKET_PATH, sizeof(addr.sun_path));
	
	if(bind(socket_fd, (struct sockaddr *) &addr, sizeof(sa_family_t) + sizeof(SERVER_SOCKET_PATH)) < 0)
	{
		throw std::runtime_error("bind failed");
	}

}

size_t Server::allocate_id()
{
	return next_wid.fetch_add(1, std::memory_order_acq_rel);
}

std::shared_ptr<Window> Server::create_window(unsigned int width,
	unsigned int height, unsigned int x, unsigned int y)
{
	auto id = allocate_id();
	std::weak_ptr<Display> weak(display);
	auto window = std::make_shared<Window>(id, height, width, x, y, weak);
	window_list.push_back(window);

	return window;
}

void Server::draw_windows()
{
	std::for_each(window_list.begin(), window_list.end(), [] (std::shared_ptr<Window> window)
	{
		if(window->is_dirty())
		{
			window->draw();
		}
	});
}
