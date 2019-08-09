/*
* Copyright (c) 2019 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#include <sys/socket.h>
#include <sys/un.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>

#include <wserver_public_api.h>

static int client_fd = -1;
static unsigned int client_id = -1;
/* Connects to the window server and does a handshake */
int wserver_connect(void)
{
	client_fd = socket(AF_UNIX, SOCK_DGRAM, 0);

	if(client_fd < 0)
		return -1;
	
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
	return 0;
}

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
	
	return NULL;
}

/* Dirties a window buffer */
int wserver_dirty_window(WINDOW window);

/* Destroys a window */
int wserver_destroy_window(WINDOW window);

/* Deletes the connection */
int wserver_goodbye(void);