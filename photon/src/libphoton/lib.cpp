/*
* Copyright (c) 2017-2020 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <string>
#include <filesystem>

#include <sys/ioctl.h>

#include <photon/photon.h>

static const std::string photon_path{"/dev/photon"};

extern "C"
{

int photon_list_devices(photon_list_device_instance *device_instances, int length) noexcept try
{
	int found_devices = 0;
	auto inst = device_instances;

	for(const auto &entry : std::filesystem::directory_iterator(photon_path))
	{
		if(entry.path().filename().string().starts_with("."))
			continue;

		found_devices++;

		if(length-- == 0)
			continue;

		strlcpy(inst->name, entry.path().c_str(), sizeof(inst->name));
	}

	return found_devices;

} catch(const std::exception &e)
{
	return -1;
}

int photon_get_bus_info(int fd, photon_bus_info *info)
{
	return ioctl(fd, PHOTON_IOCTL_GET_BUS_INFO, info);
}

int photon_get_info(int fd, photon_info *info)
{
	return ioctl(fd, PHOTON_IOCTL_GET_INFO, info);
}

int photon_create_dumb_buffer(int photon_fd, struct photon_dumb_buffer_info *info)
{
	if(ioctl(photon_fd, PHOTON_IOCTL_CREATE_DUMB_BUF, info) < 0)
	{
		perror("ioctl: PHOTON_IOCTL_CREATE_DUMB_BUF");
		return -1;
	}

	return 0;
}

int photon_swap_buffers(int photon_fd, photon_handle buffer)
{
	if(ioctl(photon_fd, PHOTON_IOCTL_SWAP_BUFS, &buffer) < 0)
	{
		perror("ioctl: PHOTON_IOCTL_SWAP_BUFS");
		return -1;
	}

	return 0;
}

int photon_create_buffer_map(int photon_fd, struct photon_create_buf_map_args *args)
{
	if(ioctl(photon_fd, PHOTON_IOCTL_CREATE_BUF_MAP, args) < 0)
	{
		perror("ioctl: PHOTON_IOCTL_CREATE_BUF_MAP");
		return -1;
	}

	return 0;
}

int photon_set_name(int photon_fd, photon_handle handle, uint64_t security_cookie, uint32_t *name)
{
	struct photon_set_name_args args;
	args.handle = handle;
	args.security_cookie = security_cookie;
	args.name = 0;

	int st = ioctl(photon_fd, PHOTON_IOCTL_SET_NAME, &args);

	*name = args.name;

	return st;
}

photon_handle photon_open_from_name(int photon_fd, uint32_t name, uint64_t security_cookie)
{
	struct photon_open_from_name_args args;
	args.handle = 0;
	args.name = name;
	args.security_cookie = security_cookie;

	if(ioctl(photon_fd, PHOTON_IOCTL_OPEN_FROM_NAME, &args) < 0)
		return PHOTON_INVALID_HANDLE;

	return args.handle;
}

int photon_close_handle(int photon_fd, photon_handle handle)
{
	struct photon_close_handle_args args;
	args.handle = handle;

	return ioctl(photon_fd, PHOTON_IOCTL_CLOSE_OBJECT, &args);
}

}
