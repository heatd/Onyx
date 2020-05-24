/*
* Copyright (c) 2017, 2018 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef PHOTON_H_INCLUDED
#define PHOTON_H_INCLUDED

#include <stdint.h>

#include <sys/types.h>

#ifdef __cplusplus
extern "C"
{
#endif

typedef uint64_t photon_handle;

#define PHOTON_INVALID_HANDLE ((photon_handle) -1)

#define PHOTON_IOCTL_CREATE_DUMB_BUF              0x00000000
#define PHOTON_IOCTL_SWAP_BUFS                    0x00000001
#define PHOTON_IOCTL_GET_VIDEOMODE                0x00000002
#define PHOTON_IOCTL_CREATE_BUF_MAP	              0x00000003
#define PHOTON_IOCTL_SET_NAME                     0x00000004
#define PHOTON_IOCTL_OPEN_FROM_NAME               0x00000005
#define PHOTON_IOCTL_CLOSE_OBJECT                 0x00000006

/* Generic max defines an upper bound for generic ioctls.
 * Anything beyond that is a driver-specific ioctl that should be handled by the
 * gpu driver.
*/
#define PHOTON_IOCTL_GENERIC_MAX		0x7fffffff

#define __PHOTON_INFO_MAX 60

struct photon_info
{
	char photon_version[__PHOTON_INFO_MAX];
	char video_driver[__PHOTON_INFO_MAX];
	char card[__PHOTON_INFO_MAX];
};


struct photon_dumb_buffer_info
{
	photon_handle handle;
	uint32_t width;
	uint32_t height;
	uint32_t bpp;
	uint32_t stride;
	uint32_t size;
};

struct photon_swap_buffer_args
{
	photon_handle buffer_handle;
};

struct photon_create_buf_map_args
{
	photon_handle handle;
	off_t offset;
};

struct photon_videomode
{
	uint32_t width;
	uint32_t height;
	uint32_t bpp;
};

struct photon_modeset_args
{
	uint32_t width;
	uint32_t height;
	uint32_t bpp;
};

struct photon_set_name_args
{
	photon_handle handle;
	/* Set name uses a security cookie as to not allow other processes to access it */
	/* User processes are expected to fill this field with secure contents */
	uint64_t security_cookie;
	/* Set by the ioctl */
	uint32_t name;
};

struct photon_open_from_name_args
{
	uint32_t name;
	uint64_t security_cookie;
	/* Set by the ioctl */
	photon_handle handle;
};

struct photon_close_handle_args
{
	photon_handle handle;
};

#ifdef __is_onyx_kernel
#define PHOTON_KERNEL_CODE
#endif

#ifndef PHOTON_KERNEL_CODE

int photon_initialize(void);
int photon_modeset(unsigned int width, unsigned int height, unsigned int bpp);

int photon_create_dumb_buffer(struct photon_dumb_buffer_info *info);
int photon_swap_buffers(photon_handle buffer);
int photon_get_videomode(struct photon_videomode *mode);
int photon_get_fd(void);
int photon_create_buffer_map(struct photon_create_buf_map_args *args);
int photon_set_name(photon_handle handle, uint64_t security_cookie, uint32_t *name);
photon_handle photon_open_from_name(uint32_t name, uint64_t security_cookie);
int photon_close_handle(photon_handle handle);

#endif

#ifdef __cplusplus
}
#endif

#endif
