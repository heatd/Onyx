/*
* Copyright (c) 2019 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#ifndef _CLIENT_H
#define _CLIENT_H

#include <vector>
#include <window.h>
#include <memory>

class Client
{
protected:
	std::vector<std::shared_ptr<Window> > client_windows;
public:
	unsigned int cid;
	Client(unsigned int cid) : cid(cid) {};
	~Client();
	void AddWindow(std::shared_ptr<Window> window);
	void DeleteWindow(size_t wid);
};

#endif