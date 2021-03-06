/*
* Copyright (c) 2021 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#include <errno.h>

#include <onyx/vfs.h>
#include <onyx/file.h>

#include <onyx/public/handle.h>
#include <onyx/expected.hpp>

namespace onx
{

namespace handle
{

#define VALID_HANDLE_OPEN_FLAGS (ONX_HANDLE_CLOEXEC)

using handle_opener = expected<file *, int> (*)(unsigned int, unsigned long, int);

#define HANDLE_OPENER(name) extern expected<file*, int> name(unsigned int, unsigned long, int);

HANDLE_OPENER(process_handle_opener);

handle_opener handle_open_handlers[] = {process_handle_opener};

int handle_open_flags_to_open(int handle_open_fl)
{
	int fl = 0;
	if(handle_open_fl & ONX_HANDLE_CLOEXEC)
		fl |= O_CLOEXEC;
	
	return fl;
}

extern "C" int sys_onx_handle_open(unsigned int resource_type, unsigned long id, int flags)
{
	if(flags & ~VALID_HANDLE_OPEN_FLAGS)
		return -EINVAL;

	if(resource_type >= (sizeof(handle_open_handlers) / sizeof(handle_open_handlers[0])))
		return -EINVAL;

	auto handle = handle_open_handlers[resource_type](resource_type, id, flags);

	if(handle.has_error())
		return handle.error();
	
	int fd = open_with_vnode(handle.value(), handle_open_flags_to_open(flags));

	// This fd_put is unconditional since open_with_vnode increments the ref on success
	fd_put(handle.value());

	return fd;
}

}

}
