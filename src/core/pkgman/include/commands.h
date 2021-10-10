/*
* Copyright (c) 2021 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#pragma once

#include <string>
#include <span>

#include <sys/stat.h>

namespace pkgman
{

namespace commands
{

int install(std::span<char *> options);
int list(std::span<char *> options);
int query(std::span<char *> options);

}

}
