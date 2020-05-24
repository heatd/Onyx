/*
* Copyright (c) 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>

#include <sys/ioctl.h>

#include <photon/photon.h>

static int photon_fd = -1;

int photon_initialize(void)
{
	photon_fd = open("/dev/photon/photon0", O_RDWR | O_CLOEXEC);
	
	if(photon_fd == -1)
	{
		perror("Error opening drm device");
		return -1;
	}

	return 0;
}

int photon_create_dumb_buffer(struct photon_dumb_buffer_info *info)
{
	if(ioctl(photon_fd, PHOTON_IOCTL_CREATE_DUMB_BUF, info) < 0)
	{
		perror("ioctl: PHOTON_IOCTL_CREATE_DUMB_BUF");
		return -1;
	}

	return 0;
}

int photon_swap_buffers(photon_handle buffer)
{
	if(ioctl(photon_fd, PHOTON_IOCTL_SWAP_BUFS, &buffer) < 0)
	{
		perror("ioctl: PHOTON_IOCTL_SWAP_BUFS");
		return -1;
	}

	return 0;
}

int photon_get_videomode(struct photon_videomode *mode)
{
	if(ioctl(photon_fd, PHOTON_IOCTL_GET_VIDEOMODE, mode) < 0)
	{
		perror("ioctl: PHOTON_IOCTL_GET_VIDEOMODE");
		return -1;
	}

	return 0;
}

int photon_get_fd(void)
{
	return photon_fd;
}

int photon_create_buffer_map(struct photon_create_buf_map_args *args)
{
	if(ioctl(photon_fd, PHOTON_IOCTL_CREATE_BUF_MAP, args) < 0)
	{
		perror("ioctl: PHOTON_IOCTL_CREATE_BUF_MAP");
		return -1;
	}

	return 0;
}

int photon_set_name(photon_handle handle, uint64_t security_cookie, uint32_t *name)
{
	struct photon_set_name_args args;
	args.handle = handle;
	args.security_cookie = security_cookie;
	args.name = 0;

	int st = ioctl(photon_fd, PHOTON_IOCTL_SET_NAME, &args);

	*name = args.name;

	return st;
}

photon_handle photon_open_from_name(uint32_t name, uint64_t security_cookie)
{
	struct photon_open_from_name_args args;
	args.handle = 0;
	args.name = name;
	args.security_cookie = security_cookie;

	if(ioctl(photon_fd, PHOTON_IOCTL_OPEN_FROM_NAME, &args) < 0)
		return PHOTON_INVALID_HANDLE;

	return args.handle;
}

int photon_close_handle(photon_handle handle)
{
	struct photon_close_handle_args args;
	args.handle = handle;

	return ioctl(photon_fd, PHOTON_IOCTL_CLOSE_OBJECT, &args);
}
