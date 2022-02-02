/*
 * Copyright (c) 2019 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 */

#include <sys/socket.h>
#include <wserver_public_api.h>

#include <cstring>
#include <iostream>

int main(int argc, char **argv, char **envp)
{
    int status = wserver_connect();

    if (status < 0)
    {
        std::cout << "Error: wserver_connect() failed\n";
        return 1;
    }

    std::cout << "singularity started!\n";

    server_message_create_window params;
    params.height = 800;
    params.width = 600;
    params.x = 100;
    params.y = 200;
    WINDOW win = wserver_create_window(&params);
    if (win == BAD_WINDOW)
    {
        std::cerr << "Error: wserver_create_window failed\n";
        perror("");
        return 1;
    }

    struct wserver_window_map map;
    map.size = wserver_get_buffer_size(params.height, params.width, 32);
    map.win = win;

    if (wserver_window_map(&map) < 0)
    {
        std::cerr << "Error: wserver_window_map() failed\n";
        return 1;
    }

    printf("map: %p\n", map.addr);
    std::memset(map.addr, 0xca, map.size);
    wserver_dirty_window(win);

    return 0;
}