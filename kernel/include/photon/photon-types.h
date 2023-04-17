/*
 * Copyright (c) 2017, 2018 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 */
#ifndef _PHOTON_PHOTON_TYPES_H
#define _PHOTON_PHOTON_TYPES_H

#include <onyx/limits.h>
#include <onyx/types.h>

#include <uapi/posix-types.h>

typedef __u64 photon_handle;

#define PHOTON_INVALID_HANDLE ((photon_handle) -1)

#define PHOTON_IOCTL_CREATE_DUMB_BUF 0x00000000
#define PHOTON_IOCTL_SWAP_BUFS       0x00000001
#define PHOTON_IOCTL_GET_VIDEOMODE   0x00000002
#define PHOTON_IOCTL_CREATE_BUF_MAP  0x00000003
#define PHOTON_IOCTL_SET_NAME        0x00000004
#define PHOTON_IOCTL_OPEN_FROM_NAME  0x00000005
#define PHOTON_IOCTL_CLOSE_OBJECT    0x00000006
#define PHOTON_IOCTL_GET_INFO        0x00000007
#define PHOTON_IOCTL_GET_BUS_INFO    0x00000008

/* Generic max defines an upper bound for generic ioctls.
 * Anything beyond that is a driver-specific ioctl that should be handled by the
 * gpu driver.
 */
#define PHOTON_IOCTL_GENERIC_MAX  0x7fffffff
#define PHOTON_IOCTL_PLATFORM_MIN (int) (((unsigned int) PHOTON_IOCTL_GENERIC_MAX + 1))
#define PHOTON_IOCTL_PLATFORM_MAX ((int) 0xffffffff)
#define __PHOTON_INFO_MAX         80

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
    __u16 segment;
    __u8 bus;
    __u8 device;
    __u8 function;
};

struct photon_pci_info
{
    struct photon_pci_address addr;
    __u16 device_id;
    __u16 vendor_id;
    __u16 subsystem_id;
};

struct photon_bus_info
{
    enum photon_bus_type type;

    union {
        struct photon_pci_info pci_info;
    } info;
};

struct photon_dumb_buffer_info
{
    photon_handle handle;
    __u32 width;
    __u32 height;
    __u32 bpp;
    __u32 stride;
    __u32 size;
};

struct photon_swap_buffer_args
{
    photon_handle buffer_handle;
};

struct photon_create_buf_map_args
{
    photon_handle handle;
    __off_t offset;
};

struct photon_videomode
{
    __u32 width;
    __u32 height;
    __u32 bpp;
};

struct photon_modeset_args
{
    __u32 width;
    __u32 height;
    __u32 bpp;
};

struct photon_set_name_args
{
    photon_handle handle;
    /* Set name uses a security cookie as to not allow other processes to access it */
    /* User processes are expected to fill this field with secure contents */
    __u64 security_cookie;
    /* Set by the ioctl */
    __u32 name;
};

struct photon_open_from_name_args
{
    __u32 name;
    __u64 security_cookie;
    /* Set by the ioctl */
    photon_handle handle;
};

struct photon_close_handle_args
{
    photon_handle handle;
};

#endif
