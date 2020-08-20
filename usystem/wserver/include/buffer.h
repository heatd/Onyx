/*
* Copyright (c) 2018 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#ifndef _BUFFER_H
#define _BUFFER_H

#include <memory>

#include <photon/photon.h>

class Display;

class Buffer
{
private:
	std::weak_ptr <Display> display;
	struct photon_dumb_buffer_info buffer_info;
	unsigned int height;
	unsigned int width;
	unsigned int bpp;
public:
	void *mapping;
	Buffer(unsigned int width, unsigned int height, unsigned int bpp,
		std::weak_ptr <Display> display);
	Buffer(unsigned int width, unsigned int height,
		std::weak_ptr <Display> display);
	void create();
	~Buffer();
	void map();
	void unmap();
	photon_handle get_handle();

	inline unsigned int get_height()
	{
		return height;
	}
	
	inline unsigned int get_width()
	{
		return width;
	}

	inline unsigned int get_bpp()
	{
		return bpp;
	}

	inline unsigned int get_stride()
	{
		return buffer_info.stride;
	}
};

#endif
