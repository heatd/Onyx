/*
* Copyright (c) 2019 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#ifndef WSERVER_PUBLIC_API
#define WSERVER_PUBLIC_API

#ifdef __cplusplus
extern "C" {
#endif

enum server_message_type
{
	SERVER_MESSAGE_CLIENT_HANDSHAKE = 0,
	SERVER_MESSAGE_CREATE_WINDOW,
	SERVER_MESSAGE_DIRTY_WINDOW,
	SERVER_MESSAGE_DESTROY_WINDOW,
	SERVER_MESSAGE_CLIENT_GOODBYE
};

struct server_message_create_window
{
	unsigned int width;
	unsigned int height;
	unsigned int x;
	unsigned int y;
};

typedef void * WINDOW;
typedef void * CLIENT_ID;

struct server_message_dirty_window
{
	WINDOW window_handle;
};

struct server_message_destroy_window
{
	WINDOW window_handle;
};


struct server_message
{
	unsigned int client_id;
	enum server_message_type msg_type;
	union
	{
		struct server_message_create_window cwargs;
		struct server_message_dirty_window dirtywargs;
		struct server_message_destroy_window destroywargs;
	} args;
};

enum server_status
{
	STATUS_OK = 0,
	STATUS_FAILURE = -1
};

struct server_message_handshake_reply
{
	unsigned int new_cid;
};

struct server_message_create_window_reply
{
	WINDOW window_handle;
};

struct server_reply
{
	enum server_status status;
	union
	{
		struct server_message_handshake_reply hrply;
		struct server_message_create_window_reply cwreply;
	} reply;
};

#define SERVER_SOCKET_PATH	"\0wserver.message_queue"

#define BAD_WINDOW		(WINDOW) -1
/* Connects to the window server and does a handshake */
int wserver_connect(void);

/* Creates a window */
WINDOW wserver_create_window(struct server_message_create_window *params);

/* Dirties a window buffer */
int wserver_dirty_window(WINDOW window);

/* Destroys a window */
int wserver_destroy_window(WINDOW window);

/* Deletes the connection */
int wserver_goodbye(void);

#ifdef __cplusplus
}
#endif

#endif