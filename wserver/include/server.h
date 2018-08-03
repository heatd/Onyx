/*
* Copyright (c) 2018 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _SERVER_H
#define _SERVER_H

#include <memory>
#include <vector>
#include <window.h>
#include <atomic>

class Display;

class Server
{
private:
	int socket_fd;
	std::shared_ptr<Display> display;
	std::vector<std::shared_ptr<Window> > window_list;
	std::atomic_size_t next_wid;
public:
	Server(std::shared_ptr<Display> display);
	std::shared_ptr<Window> create_window(unsigned int height,
		unsigned int width, unsigned int x, unsigned int y);
	void draw_windows();
	size_t allocate_id();
	void pump_message_loop();
};

#endif
