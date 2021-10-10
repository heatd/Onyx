/*
* Copyright (c) 2021 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#pragma once

#include <string>

#include <sys/stat.h>

namespace pkgman
{

bool file_exists(const std::string& path)
{
	struct stat dummy;
	return ::stat(path.c_str(), &dummy) == 0;
}

const std::string& get_sysroot();

}
