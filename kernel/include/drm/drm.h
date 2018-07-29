/*
* Copyright (c) 2017, 2018 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef DRM_H_INCLUDED
#define DRM_H_INCLUDED

#include <stdint.h>

#include <sys/types.h>

#ifdef __cplusplus
extern "C"
{
#endif

typedef uint64_t drm_handle;

#define DRM_INVALID_HANDLE ((drm_handle) -1)

#define DRM_IOCTL_CREATE_DUMB_BUF	0x00000000
#define DRM_IOCTL_SWAP_BUFS		0x00000001
#define DRM_IOCTL_GET_VIDEOMODE		0x00000002
#define DRM_IOCTL_CREATE_BUF_MAP	0x00000003

/* Generic max defines an upper bound for generic ioctls.
 * Anything beyond that is a driver-specific ioctl that should be handled by the
 * gpu driver.
*/
#define DRM_IOCTL_GENERIC_MAX		0x7fffffff

#define __DRM_INFO_MAX 60

struct drm_info
{
	char drm_version[__DRM_INFO_MAX];
	char video_driver[__DRM_INFO_MAX];
	char card[__DRM_INFO_MAX];
};


struct drm_dumb_buffer_info
{
	drm_handle handle;
	uint32_t width;
	uint32_t height;
	uint32_t bpp;
	uint32_t stride;
	uint32_t size;
};

struct drm_swap_buffer_args
{
	drm_handle buffer_handle;
};

struct drm_create_buf_map_args
{
	drm_handle handle;
	off_t offset;
};

struct drm_videomode
{
	uint32_t width;
	uint32_t height;
	uint32_t bpp;
};

struct drm_modeset_args
{
	uint32_t width;
	uint32_t height;
	uint32_t bpp;
};

#ifndef __is_onyx_kernel
int drm_initialize(void);
int drm_modeset(unsigned int width, unsigned int height, unsigned int bpp);

int drm_create_dumb_buffer(struct drm_dumb_buffer_info *info);
int drm_swap_buffers(drm_handle buffer);
int drm_get_videomode(struct drm_videomode *mode);
int drm_get_fd(void);
int drm_create_buffer_map(struct drm_create_buf_map_args *args);

#endif

#ifdef __cplusplus
}
#endif

#endif
