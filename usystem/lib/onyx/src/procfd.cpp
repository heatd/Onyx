/*
* Copyright (c) 2021 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#include <errno.h>

#include <libonyx/procfd.h>

int onx_process_open(pid_t pid, int flags)
{
	errno = EINVAL;
	return -1;
}

void onx_process_close(int fd)
{
	::close(fd);
}
