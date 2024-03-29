/*
 * Copyright (c) 2018 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 */

#define _XOPEN_SOURCE 500
#include <assert.h>
#include <client.h>
#include <display.h>
#include <err.h>
#include <fcntl.h>
#include <server.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>
#include <window.h>
#include <wserver_public_api.h>

#include <algorithm>
#include <iostream>

Server::Server(std::shared_ptr<Display> display) : display(display), window_list()
{
    socket_fd = socket(AF_UNIX, SOCK_DGRAM, 0);

    if (socket_fd < 0)
    {
        throw std::runtime_error("socket failed");
    }

    struct sockaddr_un addr;
    addr.sun_family = AF_UNIX;
    memcpy(addr.sun_path, SERVER_SOCKET_PATH, sizeof(SERVER_SOCKET_PATH));

    if (bind(socket_fd, (struct sockaddr *) &addr,
             sizeof(sa_family_t) + sizeof(SERVER_SOCKET_PATH)) < 0)
    {
        throw std::runtime_error("bind failed");
    }
}

size_t Server::allocate_wid()
{
    return next_wid.fetch_add(1, std::memory_order_acq_rel);
}

std::shared_ptr<Window> Server::create_window(unsigned int width, unsigned int height,
                                              unsigned int x, unsigned int y)
{
    auto id = allocate_wid();
    std::weak_ptr<Display> weak(display);
    auto window = std::make_shared<Window>(id, height, width, x, y, weak);
    window_list.push_back(window);

    return window;
}

unsigned int Server::allocate_cid()
{
    return next_cid.fetch_add(1, std::memory_order_acq_rel);
}

unsigned int Server::create_client()
{
    auto cid = allocate_cid();
    clients[cid] = std::move(std::make_shared<Client>(cid));

    return cid;
}

std::shared_ptr<Client> Server::get_client(unsigned int cid)
{
    auto cptr = clients[cid];

    if (!cptr)
        return nullptr;
    return cptr;
}

class ServerReply
{
public:
    struct server_reply reply;
    struct sockaddr *addr;
    socklen_t len;
    int socket_fd;
    ServerReply(struct sockaddr *addr, socklen_t len, int socket_fd)
        : addr(addr), len(len), socket_fd(socket_fd)
    {
        memset(&reply, 0, sizeof(struct server_reply));
    }

    void set_status_code(enum server_status st)
    {
        reply.status = st;
    }

    void set_handshake_reply(struct server_message_handshake_reply &hreply)
    {
        reply.reply.hrply.new_cid = hreply.new_cid;
    }

    void set_create_window_reply(struct server_message_create_window_reply &cwreply)
    {
        reply.reply.cwreply.window_handle = cwreply.window_handle;
    }

    void set_get_window_buffer_handle_reply(struct server_message_get_window_buffer_handle_reply &r)
    {
        reply.reply.gwbhreply = r;
    }

    void send()
    {
        if (sendto(socket_fd, &reply, sizeof(struct server_reply), 0, addr, len) < 0)
        {
            /* TODO: Write to a log file */
            perror("sendto");
        }
    }
};

void Server::handle_message(struct server_message *msg, struct sockaddr *addr, socklen_t len)
{
    switch (msg->msg_type)
    {
    case SERVER_MESSAGE_CLIENT_HANDSHAKE: {
        std::cout << "Handling a client handshake\n";
        auto cid = create_client();
        struct server_message_handshake_reply hreply;
        hreply.new_cid = cid;
        /* Craft a reply containing the return cid */
        ServerReply reply(addr, len, socket_fd);
        reply.set_status_code(STATUS_OK);
        reply.set_handshake_reply(hreply);
        reply.send();
        break;
    }
    case SERVER_MESSAGE_CREATE_WINDOW: {
        std::cout << "Creating window\n";
        auto &cwargs = msg->args.cwargs;
        ServerReply reply(addr, len, socket_fd);

        auto client = get_client(msg->client_id);
        if (!client)
        {
            reply.set_status_code(STATUS_FAILURE);
            reply.send();
            break;
        }

        auto window = create_window(cwargs.width, cwargs.height, cwargs.x, cwargs.y);

        if (!window)
        {
            reply.set_status_code(STATUS_FAILURE);
            reply.send();
            break;
        }

        window->draw();

        WINDOW window_handle = client->create_window(window);
        /* TODO: Delete window on client->create_window() failure */
        // TODO: Actually I think that's getting deleted.

        server_message_create_window_reply r;
        r.window_handle = window_handle;

        reply.set_status_code(STATUS_OK);
        reply.set_create_window_reply(r);
        reply.send();
        break;
    }
    case SERVER_MESSAGE_GET_WINDOW_BUFFER_HANDLE: {
        auto &gwbargs = msg->args.gwbhargs;
        ServerReply reply(addr, len, socket_fd);

        auto client = get_client(msg->client_id);
        if (!client)
        {
            reply.set_status_code(STATUS_FAILURE);
            reply.send();
            break;
        }

        auto window = client->get_window(gwbargs.window_handle);

        if (!window)
        {
            reply.set_status_code(STATUS_FAILURE);
            reply.send();
            break;
        }

        auto buffer = window->get_buffer();
        server_message_get_window_buffer_handle_reply r;
        uint32_t name;
        uint64_t cookie = random();
#if 0
			if(photon_set_name(buffer->get_handle(), cookie, &name) < 0)
				perror("photon_set_name");
			r.photon_name = name;
			r.security_cookie = cookie;
			reply.set_status_code(STATUS_OK);
			reply.set_get_window_buffer_handle_reply(r);
#else
        reply.set_status_code(STATUS_FAILURE);
#endif
        reply.send();
        break;
    }
    case SERVER_MESSAGE_DIRTY_WINDOW: {
        auto &dwargs = msg->args.dirtywargs;
        bool dont_reply = dwargs.dont_reply;
        ServerReply reply(addr, len, socket_fd);

        auto client = get_client(msg->client_id);
        if (!client)
        {
            if (dont_reply)
                break;
            reply.set_status_code(STATUS_FAILURE);
            reply.send();
            break;
        }

        auto window = client->get_window(dwargs.window_handle);

        if (!window)
        {
            if (dont_reply)
                break;
            reply.set_status_code(STATUS_FAILURE);
            reply.send();
            break;
        }

        window->set_dirty();
        if (dont_reply == false)
        {
            reply.set_status_code(STATUS_OK);
            reply.send();
        }

        break;
    }
    default: {
        std::cout << "Unhandled message type " << msg->msg_type << "\n";
        ServerReply reply(addr, len, socket_fd);
        reply.set_status_code(STATUS_FAILURE);
        reply.send();
        break;
    }
    }
}

void Server::handle_events()
{
    struct server_message msg;
    struct sockaddr_un client_addr;
    socklen_t len = sizeof(client_addr);

    while (recvfrom(socket_fd, &msg, sizeof(struct server_message), 0,
                    (struct sockaddr *) &client_addr, &len))
    {
        handle_message(&msg, (struct sockaddr *) &client_addr, len);
    }

    perror("recvfrom");
}
