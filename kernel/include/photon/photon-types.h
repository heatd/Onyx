/*
* Copyright (c) 2017, 2018 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _PHOTON_PHOTON_TYPES_H
#define _PHOTON_PHOTON_TYPES_H

#include <stdint.h>
#include <onyx/limits.h>

#include <sys/types.h>

typedef uint64_t photon_handle;

#define PHOTON_INVALID_HANDLE ((photon_handle) -1)

#define PHOTON_IOCTL_CREATE_DUMB_BUF              0x00000000
#define PHOTON_IOCTL_SWAP_BUFS                    0x00000001
#define PHOTON_IOCTL_GET_VIDEOMODE                0x00000002
#define PHOTON_IOCTL_CREATE_BUF_MAP	              0x00000003
#define PHOTON_IOCTL_SET_NAME                     0x00000004
#define PHOTON_IOCTL_OPEN_FROM_NAME               0x00000005
#define PHOTON_IOCTL_CLOSE_OBJECT                 0x00000006
#define PHOTON_IOCTL_GET_INFO                     0x00000007
#define PHOTON_IOCTL_GET_BUS_INFO                 0x00000008

/* Generic max defines an upper bound for generic ioctls.
 * Anything beyond that is a driver-specific ioctl that should be handled by the
 * gpu driver.
*/
#define PHOTON_IOCTL_GENERIC_MAX		0x7fffffff
#define PHOTON_IOCTL_PLATFORM_MIN       (int)(((unsigned int) PHOTON_IOCTL_GENERIC_MAX + 1))
#define PHOTON_IOCTL_PLATFORM_MAX       ((int) 0xffffffff)
#define __PHOTON_INFO_MAX 80

struct photon_info
{
	char photon_version[__PHOTON_INFO_MAX];
	char driver_name[__PHOTON_INFO_MAX];
	char driver_version[__PHOTON_INFO_MAX];
};

enum photon_bus_type
{
	PHOTON_BUS_PCI = 0,
	PHOTON_BUS_PLATFORM
};

struct photon_pci_address
{
	uint16_t segment;
	uint8_t bus;
	uint8_t device;
	uint8_t function;
};

struct photon_pci_info
{
	struct photon_pci_address addr;
	uint16_t device_id;
	uint16_t vendor_id;
	uint16_t subsystem_id;
};

struct photon_bus_info
{
	enum photon_bus_type type;

	union
	{
		struct photon_pci_info pci_info;
	} info;
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

#endif
