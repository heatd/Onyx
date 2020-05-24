/*
* Copyright (c) 2019 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>

#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <wserver_public_api.h>

static int client_fd = -1;
static unsigned int client_id = -1;
/* Connects to the window server and does a handshake */
int wserver_connect(void)
{
	/* TODO: Implement SOCK_CLOEXEC on sys_socket */
	client_fd = socket(AF_UNIX, SOCK_DGRAM, 0);

	if(client_fd < 0)
		return -1;

	fcntl(client_fd, F_SETFD, FD_CLOEXEC);

	struct sockaddr_un addr = {};
	addr.sun_family = AF_UNIX;
	memcpy(addr.sun_path, SERVER_SOCKET_PATH, sizeof(SERVER_SOCKET_PATH));

	if(connect(client_fd, (struct sockaddr *) &addr,
		sizeof(addr.sun_family) + sizeof(SERVER_SOCKET_PATH)) < 0)
	{
		perror("wserver_connect: connect");
		close(client_fd);
		return -1;
	}

	struct server_message msg = {};
	struct server_reply reply = {};

	msg.client_id = -1;
	msg.msg_type = SERVER_MESSAGE_CLIENT_HANDSHAKE;
	
	if(send(client_fd, &msg, sizeof(msg), 0) < 0)
	{
		perror("wserver_connect: send");
		close(client_fd);
		return -1;
	}

	if(recv(client_fd, &reply, sizeof(reply), 0) < 0)
	{
		perror("wserver_connect: recv");
		close(client_fd);
		return -1;
	}

	if(reply.status != STATUS_OK)
	{
		printf("wserver_connect: Bad reply %x", reply.status);
		close(client_fd);
		return -1;
	}

	client_id = reply.reply.hrply.new_cid;

	photon_initialize();

	return 0;
}

photon_handle wserver_get_handle_for_window(WINDOW window);

/* Creates a window */
WINDOW wserver_create_window(struct server_message_create_window *params)
{
	struct server_message msg = {};
	msg.client_id = client_id;
	msg.msg_type = SERVER_MESSAGE_CREATE_WINDOW;

	memcpy(&msg.args.cwargs, params, sizeof(*params));

	if(send(client_fd, &msg, sizeof(msg), 0) < 0)
	{
		perror("wserver_create_window: send");
		return BAD_WINDOW;
	}

	struct server_reply reply = {};

	if(recv(client_fd, &reply, sizeof(reply), 0) < 0)
	{
		perror("wserver_create_window: recv");
		return BAD_WINDOW;
	}

	if(reply.status != STATUS_OK)
		return BAD_WINDOW;
	
	return reply.reply.cwreply.window_handle;
}

photon_handle wserver_get_handle_for_window(WINDOW window)
{
	struct server_message msg = {};
	msg.client_id = client_id;
	msg.msg_type = SERVER_MESSAGE_GET_WINDOW_BUFFER_HANDLE;

	msg.args.gwbhargs.window_handle = window;

	if(send(client_fd, &msg, sizeof(msg), 0) < 0)
	{
		perror("wserver_get_handle_for_window: send");
		return PHOTON_INVALID_HANDLE;
	}

	struct server_reply reply = {};

	if(recv(client_fd, &reply, sizeof(reply), 0) < 0)
	{
		perror("wserver_get_handle_for_window: recv");
		return PHOTON_INVALID_HANDLE;
	}

	if(reply.status != STATUS_OK)
		return PHOTON_INVALID_HANDLE;

	photon_handle h = photon_open_from_name(reply.reply.gwbhreply.photon_name,
		reply.reply.gwbhreply.security_cookie);
	return h;
}

void *wserver_map_photon_buf(size_t size, size_t off, photon_handle handle)
{
	int photon_fd = photon_get_fd();
	struct photon_create_buf_map_args args;
	args.handle = handle;
	
	if(photon_create_buffer_map(&args) < 0)
		return NULL;
	return mmap(NULL, size, PROT_WRITE | PROT_READ, MAP_SHARED, photon_fd, args.offset);
}

int wserver_window_map(struct wserver_window_map *map)
{
	photon_handle handle = wserver_get_handle_for_window(map->win);

	if(handle == PHOTON_INVALID_HANDLE)
		return -1;
	map->addr = wserver_map_photon_buf(map->size, 0, handle);
	return map->addr != MAP_FAILED ? 0 : -1;
}

/* Dirties a window buffer */
int wserver_dirty_window(WINDOW window)
{
	struct server_message msg = {};
	msg.client_id = client_id;
	msg.msg_type = SERVER_MESSAGE_DIRTY_WINDOW;
	msg.args.dirtywargs.dont_reply = true;
	msg.args.dirtywargs.window_handle = window;

	if(send(client_fd, &msg, sizeof(msg), 0) < 0)
	{
		perror("wserver_dirty_window: send");
		return -1;
	}

	return 0;
}

/* Destroys a window */
int wserver_destroy_window(WINDOW window);

/* Deletes the connection */
int wserver_goodbye(void);
