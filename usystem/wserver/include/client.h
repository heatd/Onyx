/*
 * Copyright (c) 2019 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 */

#ifndef _CLIENT_H
#define _CLIENT_H

#include <window.h>
#include <wserver_public_api.h>

#include <memory>
#include <mutex>
#include <vector>

class Client
{
protected:
    std::vector<std::shared_ptr<Window>> client_windows;
    std::mutex client_windows_lock;

public:
    unsigned int cid;
    Client(unsigned int cid) : cid(cid){};
    ~Client();
    void DeleteWindow(size_t wid);
    std::shared_ptr<Window> get_window(WINDOW handle);
    WINDOW create_window(std::shared_ptr<Window> window);
};

#endif