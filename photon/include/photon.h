/*
 * Copyright (c) 2020 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 */

#ifndef _PHOTON_H
#define _PHOTON_H

#include <photon/photon-types.h>

struct photon_list_device_instance
{
    char name[NAME_MAX];
};

#ifdef __cplusplus
extern "C" {
#endif

int photon_list_devices(struct photon_list_device_instance *device_instances, int length);
int photon_get_info(int fd, struct photon_info *info);
int photon_get_bus_info(int fd, struct photon_bus_info *info);
int photon_modeset(int fd, unsigned int width, unsigned int height, unsigned int bpp);

int photon_create_dumb_buffer(int fd, struct photon_dumb_buffer_info *info);
int photon_swap_buffers(int fd, photon_handle buffer);
int photon_create_buffer_map(int fd, struct photon_create_buf_map_args *args);
int photon_set_name(int fd, photon_handle handle, uint64_t security_cookie, uint32_t *name);
photon_handle photon_open_from_name(int fd, uint32_t name, uint64_t security_cookie);
int photon_close_handle(int fd, photon_handle handle);

#ifdef __cplusplus
}
#endif

#endif
