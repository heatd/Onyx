/*
* Copyright (c) 2021 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#include <errno.h>
#include <unistd.h>

#include <libonyx/handle.h>

#include <sys/syscall.h>

int onx_handle_open(unsigned int resource_type, unsigned long id, int flags)
{
	return syscall(SYS_onx_handle_open, resource_type, id, flags);
}

void onx_handle_close(int handle)
{
	::close(handle);
}

ssize_t onx_handle_query(int handle, void *buffer, ssize_t len, unsigned long what, size_t *howmany,
                                        void *arg)
{
	return syscall(SYS_onx_handle_query, handle, buffer, len, what, howmany, arg);
}
