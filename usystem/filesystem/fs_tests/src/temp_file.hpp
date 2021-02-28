/*
* Copyright (c) 2021 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#pragma once

#include <unistd.h>
#include <fcntl.h>
#include <cstdlib>
#include <stdexcept>
#include <system_error>

class temp_file
{
private:
	int fd;
	static constexpr std::size_t file_name_size = 16; 
	char file_name[file_name_size];
public:
	temp_file() : fd{-1}, file_name{"file-testXXXXXX"}
	{
		fd = mkstemp(file_name);
		if(fd < 0)
		{
			throw std::system_error(errno, std::generic_category(), "Failed to create file test");
		}
	}

	~temp_file()
	{
		sync();
		if(unlink(file_name) < 0)
			throw std::system_error(errno, std::generic_category(), "Failed to unlink");
		close(fd);
	}

	void sync() const
	{
		if(fsync(fd) < 0)
			throw std::system_error(errno, std::generic_category(), "Failed to sync file");
	}

	int get_fd() const
	{
		return fd;
	}
};
