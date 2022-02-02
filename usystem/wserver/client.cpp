/*
 * Copyright (c) 2019 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 */
#include <assert.h>
#include <client.h>

#include <algorithm>

Client::~Client()
{
}

void Client::DeleteWindow(size_t wid)
{
    std::scoped_lock guard{client_windows_lock};

    std::ptrdiff_t idx = -1;
    for (auto it = client_windows.begin(); it != client_windows.end(); ++it)
    {
        auto window = *it;

        if (window->window_id == wid)
        {
            idx = std::distance(client_windows.begin(), it);
            break;
        }
    }

    assert(idx != -1);

    client_windows.erase(client_windows.begin() + idx);
}

std::shared_ptr<Window> Client::get_window(WINDOW handle)
{
    std::scoped_lock guard{client_windows_lock};
    size_t index = (size_t)handle;

    if (index >= client_windows.size())
        return nullptr;

    return client_windows[index];
}

WINDOW Client::create_window(std::shared_ptr<Window> window)
{
    std::scoped_lock guard{client_windows_lock};
    client_windows.push_back(window);
    return (void *)(client_windows.size() - 1);
}