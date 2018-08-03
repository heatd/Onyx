/*
* Copyright (c) 2018 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#ifndef _WINDOW_H
#define _WINDOW_H
#include <stddef.h>
#include <memory>
#include <display.h>

class Window
{
private:
	size_t window_id;
	unsigned int x;
	unsigned int y;
	unsigned int width;
	unsigned int height;
	bool dirty;
	std::weak_ptr<Display> display;
	std::shared_ptr<Buffer> window_buffer;
public:
	Window(size_t window_id, unsigned int width, 
		unsigned int height, unsigned int x, unsigned int y,
		std::weak_ptr <Display> display);
	~Window();

	inline bool is_dirty()
	{
		return dirty;
	}

	inline void set_dirty()
	{
		dirty = true;
	}

	void draw();
};



#endif
