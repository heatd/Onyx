/*
* Copyright (c) 2018 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#include <window.h>
#include <iostream>

Window::Window(size_t window_id, unsigned int width,
		unsigned int height, unsigned int x, unsigned int y,
		std::weak_ptr <Display> display) : window_id(window_id),
		width(width), height(height), x(x), y(y), display(display),
		dirty(false)
{
	auto buffer = std::make_shared<Buffer>(width, height, display);
	
	/* Don't forget to map the buffer! */
	buffer->map();

	window_buffer = buffer;
}

void Window::draw()
{
	if(auto disp = display.lock())
	{
		disp->copy(window_buffer, x, y);
		disp->swap();
	}
	else
		throw std::runtime_error("Invalid display");

	dirty = false;
}

Window::~Window()
{
}