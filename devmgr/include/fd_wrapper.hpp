/*
* Copyright (c) 2020 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#ifndef _FD_WRAPPER_HPP
#define _FD_WRAPPER_HPP

#include <unistd.h>

class unique_fd
{
private:
	int fd;
public:
	unique_fd(int fd) : fd(fd) {}
	~unique_fd() { close(fd); }

	operator int()
	{
		return fd;
	}

	int get_fd()
	{
		return fd;
	}
};

#endif