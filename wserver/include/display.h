/*
* Copyright (c) 2018 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#ifndef _DISPLAY_H
#define _DISPLAY_H

#include <vector>
#include <memory>

#include <buffer.h>

#include <drm/drm.h>

class Display : public std::enable_shared_from_this<Display>
{
private:
	struct drm_videomode videomode;
	std::vector<std::shared_ptr<Buffer> > buffer_list;
	std::unique_ptr<Buffer> framebuffer_map;
public:
	Display();
	~Display();
	unsigned int get_bpp()
	{
		return videomode.bpp;
	};

	std::shared_ptr <Buffer> create_buffer(unsigned int height, unsigned int width);
	void swap();
	void copy(std::shared_ptr<Buffer> buffer, unsigned int x, unsigned int y);
	void GetOwnershipOfDisplay();
	void ReleaseOwnershipOfDisplay();
	void Clear(uint32_t color);
	void draw_loop();
};

#endif
