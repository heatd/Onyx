/*
 * Copyright (c) 2018 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 */
#ifndef _SERVER_H
#define _SERVER_H

#include <sys/socket.h>
#include <window.h>

#include <atomic>
#include <map>
#include <memory>
#include <vector>

class Display;
class Client;
struct server_message;
struct server_reply;

class Server
{
private:
    int socket_fd;
    std::shared_ptr<Display> display;
    std::vector<std::shared_ptr<Window>> window_list;
    std::map<unsigned int, std::shared_ptr<Client>> clients;
    std::atomic_size_t next_wid;
    std::atomic_uint next_cid;
    void handle_message(struct server_message *msg, struct sockaddr *addr, socklen_t len);
    unsigned int allocate_cid();
    unsigned int create_client();
    void send_reply(struct server_reply *reply, struct sockaddr *addr, socklen_t len);

public:
    Server(std::shared_ptr<Display> display);
    Server(){};

    Server &operator=(const Server &a)
    {
        return (Server &)a;
    }

    std::shared_ptr<Window> create_window(unsigned int height, unsigned int width, unsigned int x,
                                          unsigned int y);
    size_t allocate_wid();
    void handle_events();
    std::shared_ptr<Client> get_client(unsigned int cid);
};

#endif
