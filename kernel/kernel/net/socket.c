/*
* Copyright (c) 2018 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#include <onyx/utils.h>
#include <onyx/socket.h>

void socket_release(struct object *obj)
{
	struct socket *socket = (struct socket *) container_of(obj, struct socket, object);

	if(socket->dtor)	socket->dtor(socket);

	free(socket);
}

void socket_init(struct socket *socket)
{
	object_init(&socket->object, socket_release);
}

void socket_ref(struct socket *socket)
{
	object_ref(&socket->object);
}

void socket_unref(struct socket *socket)
{
	object_unref(&socket->object);
}