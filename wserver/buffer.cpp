/*
* Copyright (c) 2018 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#include <buffer.h>
#include <display.h>
#include <string>
#include <string.h>

#include <iostream>

#include <sys/mman.h>

#include <drm/drm.h>

Buffer::Buffer(unsigned int width, unsigned int height, unsigned int bpp, std::weak_ptr<Display> display)
	: height(height), width(width), bpp(bpp), display(display), mapping(nullptr)
{
	memset(&buffer_info, 0, sizeof(buffer_info));
	this->create();
}

Buffer::Buffer(unsigned int width, unsigned int height, std::weak_ptr <Display> display)
	: height(height), width(width), display(display), mapping(nullptr)
{
	if(auto disp = display.lock())
		bpp = disp->get_bpp();
	else
		throw std::runtime_error("Display weak_ptr expired");
	this->create();
}

void Buffer::create()
{
	buffer_info.bpp = bpp;
	buffer_info.height = height;
	buffer_info.width = width;

	if(drm_create_dumb_buffer(&buffer_info) < 0)
		throw std::runtime_error("drm_create_dumb_buffer failed");
}

void Buffer::map()
{
	struct drm_create_buf_map_args args;
	args.handle = buffer_info.handle;

	if(drm_create_buffer_map(&args) < 0)
		throw std::runtime_error("drm_create_buffer_map: Failure to"
			"create buffer mapping");
	
	mapping = mmap(NULL, buffer_info.size, PROT_READ | PROT_WRITE, MAP_SHARED, drm_get_fd(),
		args.offset);
	if(mapping == MAP_FAILED)
		throw std::runtime_error("mmap failed");
}

void Buffer::unmap()
{
	std::cout << "unmapping buffer\n";
	if(!mapping)
		throw std::runtime_error("unmap() failed: Buffer not mapped");
	if(munmap(mapping, buffer_info.size) < 0)
		throw std::runtime_error("unmap() failed: munmap failed");
}

Buffer::~Buffer()
{
	/*if(mapping)
		unmap();*/
	/* TODO: Add drm buffer destruction once it's implemented */
}

drm_handle Buffer::get_handle()
{
	return buffer_info.handle;
}