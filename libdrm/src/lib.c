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
int drm_request_info(struct drm_info *info)
{
	if(!info)
		return -1;
	if(ioctl(drm_fd, DRM_REQUEST_DRMINFO, info) < 0)
	{
		printf("libdrm: %s: DRM_REQUEST_DRMINFO failed!\n", __func__);
		return -1;
	}
	return 0;
}
int drm_initialize(struct drm_info **out)
{
	drm_fd = open("/dev/drm", O_RDWR);
	
	if(drm_fd == -1)
	{
		printf("libdrm: /dev/drm not found!\n");
		return -1;
	}
	/* TODO: When lsmod(2) gets implemented, use it to check if drm is loaded in case of an error */
	struct drm_info *buf = malloc(sizeof(struct drm_info));
	if(!buf)
	{
		perror("libdrm");
		return -1;
	}
	memset(buf, 0, sizeof(struct drm_info));
	if(drm_request_info(buf) < 0)
		return -1;
	*out = buf;

	return 0;
}
int drm_modeset(unsigned int width, unsigned int height, unsigned int bpp)
{
	if(ioctl(drm_fd, DRM_REQUEST_MODESET, width, height, bpp) < 0)
	{
		printf("libdrm: %s: DRM_REQUEST_DRMINFO failed!\n", __func__);
		return -1;
	}
	return 0;
}
struct drm_fb *drm_map_fb(void)
{
	struct drm_fb *fb = malloc(sizeof(struct drm_fb));
	if(!fb)
		return NULL;
	if(ioctl(drm_fd, DRM_REQUEST_GET_FB, fb) < 0)
	{
		printf("libdrm: %s: DRM_REQUEST_GET_FB failed!\n", __func__);
		free(fb);
		return NULL;
	}
	return fb;
}