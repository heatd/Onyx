/*
* Copyright (c) 2021 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#pragma once

#include <vector>


#include <backend/package.h>

namespace pkgman
{

namespace backend
{

class database
{
private:
	std::string path;
	
	// Reference fd, that will be useful so we can refer to internal paths without having to append strings
	int fd;
	bool rdonly;

	std::vector<package> packages;

	void lock_database();
	void unlock_database();
	void load();
public:
	database(const std::string& path, bool readonly);
	~database();

	const std::vector<package>& get_package_list() const;
};

database open_database(bool readonly);
}

}
