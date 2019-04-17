/*
* Copyright (c) 2019 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <algorithm>
#include <assert.h>

#include <client.h>

Client::~Client()
{
}

void Client::AddWindow(std::shared_ptr<Window> window)
{
	client_windows.push_back(window);
}

void Client::DeleteWindow(size_t wid)
{
	std::ptrdiff_t idx = -1;
	for(auto it = client_windows.begin(); it != client_windows.end(); ++it)
	{
		std::shared_ptr<Window> window = *it;

		if(window->window_id == wid)
		{
			idx = std::distance(client_windows.begin(), it);
			break;
		}
	}

	assert(idx != -1);

	client_windows.erase(client_windows.begin() + idx);
}