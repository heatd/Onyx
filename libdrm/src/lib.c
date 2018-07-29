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

#include <drm/drm.h>

int drm_fd = -1;

int drm_initialize(void)
{
	drm_fd = open("/dev/drm/drm0", O_RDWR);
	
	if(drm_fd == -1)
	{
		printf("libdrm: /dev/drm/drm0 not found!\n");
		return -1;
	}

	return 0;
}

int drm_create_dumb_buffer(struct drm_dumb_buffer_info *info)
{
	if(ioctl(drm_fd, DRM_IOCTL_CREATE_DUMB_BUF, info) < 0)
	{
		perror("ioctl: DRM_IOCTL_CREATE_DUMB_BUF");
		return -1;
	}

	return 0;
}

int drm_swap_buffers(drm_handle buffer)
{
	if(ioctl(drm_fd, DRM_IOCTL_SWAP_BUFS, &buffer) < 0)
	{
		perror("ioctl: DRM_IOCTL_SWAP_BUFS");
		return -1;
	}

	return 0;
}

int drm_get_videomode(struct drm_videomode *mode)
{
	if(ioctl(drm_fd, DRM_IOCTL_GET_VIDEOMODE, mode) < 0)
	{
		perror("ioctl: DRM_IOCTL_GET_VIDEOMODE");
		return -1;
	}

	return 0;
}

int drm_get_fd(void)
{
	return drm_fd;
}

int drm_create_buffer_map(struct drm_create_buf_map_args *args)
{
	if(ioctl(drm_fd, DRM_IOCTL_CREATE_BUF_MAP, args) < 0)
	{
		perror("ioctl: DRM_IOCTL_CREATE_BUF_MAP");
		return -1;
	}

	return 0;
}