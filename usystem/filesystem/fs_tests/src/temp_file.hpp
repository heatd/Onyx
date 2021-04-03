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
	static constexpr std::size_t file_name_size = 40; 
	char file_name[file_name_size];
	bool delete_file;
public:
	temp_file() : fd{-1}, file_name{"file-testXXXXXX"}, delete_file{true}
	{
		fd = mkstemp(file_name);
		if(fd < 0)
		{
			throw std::system_error(errno, std::generic_category(), "Failed to create file test");
		}
	}

	temp_file(const std::string& fname) : fd{-1}, file_name{}, delete_file{true}
	{
		strcpy(file_name, fname.c_str());
		fd = mkstemp(file_name);
		if(fd < 0)
		{
			throw std::system_error(errno, std::generic_category(), "Failed to create file test");
		}
	}

	~temp_file()
	{
		sync();
		if(delete_file)
		{
			unlink(file_name);
			struct stat buf;
			assert(::stat(file_name, &buf) == -1);
			assert(errno == ENOENT);
		}

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

	void dont_delete()
	{
		delete_file = false;
	}

	char *get_file_name()
	{
		return file_name;
	}
};
