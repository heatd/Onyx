/*
* Copyright (c) 2018 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <assert.h>
#include <stdio.h>

#include <onyx/dev.h>
#include <onyx/ip.h>
#include <onyx/network.h>
#include <onyx/netif.h>
#include <onyx/compiler.h>
#include <onyx/utils.h>

#include <netinet/in.h>

#include <sys/types.h>
#include <sys/un.h>

struct unix_packet
{
	const void *buffer;
	size_t size;
	struct unix_packet *next;
};

struct un_socket
{
	socket_t socket;
	struct unix_packet *packets;
	spinlock_t packet_list_lock;
	int type;
	struct un_name *abstr_name;

	char *dest_address;
	size_t namelen;
	bool dest_is_abstract;
};

struct un_name
{
	char *address;
	size_t namelen;

	struct un_socket *bound_socket;
	struct un_name *next;
};

struct un_name *un_namespace_list = NULL;
spinlock_t un_namespace_list_lock;

struct un_name *add_to_namespace(char *address, size_t namelen,
	struct un_socket *bound_socket)
{
	struct un_name *name = zalloc(sizeof(*name));
	if(!name)
		goto cleanup_and_die;
	
	char *newbuffer = memdup(address, namelen);
	if(!newbuffer)
		goto cleanup_and_die;
		
	name->address = newbuffer;
	name->bound_socket = bound_socket;

	bound_socket->abstr_name = name;

	name->namelen = namelen;
	
	
	acquire_spinlock(&un_namespace_list_lock);

	struct un_name **pp = &un_namespace_list;

	while(*pp)
		pp = &(*pp)->next;

	*pp = name;

	return name;
cleanup_and_die:
	if(name)
	{
		if(newbuffer)	free(newbuffer);
		free(name);
	}

	return NULL;
}

int un_get_address(const struct sockaddr_un *un, socklen_t addrlen,
	char **name, size_t *pnamelen, bool *is_abstract_address)
{
	char *address = (char*) un->sun_path;
	bool _is_abstract_address = false;

	if(addrlen == sizeof(sa_family_t))
		return -EINVAL;

	size_t namelen = addrlen - sizeof(sa_family_t);

	/* See if the address is abstract or a filesystem name */
	
	/* Abstract UNIX addresses start with a NULL byte, and may not be 
	 * valid C strings, since they can have NULL bytes in the middle of the
	 * address.
	*/
	if(address[0] == '\0')
	{
		address++;
		namelen--;
		_is_abstract_address = true;
	}

	*is_abstract_address = _is_abstract_address;
	*name = address;
	*pnamelen = namelen;

	return 0;
}

int un_do_bind(const struct sockaddr_un *un, socklen_t addrlen, struct un_socket *socket)
{
	char *address;
	size_t namelen;
	bool is_abstract;

	int status = 0;
	if((status = un_get_address(un, addrlen, &address, &namelen,
		&is_abstract)) < 0)
	{
		return status;
	}

	if(!is_abstract)
	{
		/* TODO: This doesn't work! */
		struct inode *inode = creat_vfs(get_fs_root(), address, 0666);
		if(!inode)
			return -errno;

		inode->i_rdev = (dev_t) socket;

		return 0;
	}
	else
	{
		if(!add_to_namespace(address, namelen, socket))
			return -ENOMEM;
	}
	
	return 0;
}

int un_bind(const struct sockaddr *addr, socklen_t addrlen, struct inode *vnode)
{
	struct un_socket *socket = (struct un_socket*) vnode;
	if(socket->socket.bound)
		return -EINVAL;

	const struct sockaddr_un *un = (const struct sockaddr_un *) addr;

	int st = un_do_bind(un, addrlen, socket);

	if(st == 0)
		socket->socket.bound = true;
	return st;
}

int un_connect(const struct sockaddr *addr, socklen_t addrlen, struct inode *vnode)
{
	//struct un_socket *socket = (struct un_socket*) vnode;

	const struct sockaddr_un *un = (const struct sockaddr_un *) addr;
	char *address;
	size_t namelen;
	bool is_abstract;

	int status = 0;
	if((status = un_get_address(un, addrlen, &address, &namelen,
		&is_abstract)) < 0)
	{
		return status;
	}

	char *new_name = memdup(address, namelen);

	if(!new_name)
		return -ENOMEM;
	
	if(is_abstract)
	{
		assert(0);
	}
	else
	{
		assert(is_abstract != true);
	}

	return 0;
}
ssize_t un_send(const void *buf, size_t len, int flags, struct inode *vnode)
{
	return 0;
}
ssize_t un_recvfrom(void *buf, size_t len, int flags, struct sockaddr *addr, 
		socklen_t *slen, struct inode *vnode)
{
	return 0;
}

static struct file_ops un_ops = 
{
	.bind = un_bind,
	.connect = un_connect,
	.send = un_send,
	.recvfrom = un_recvfrom
};

socket_t *unix_create_socket(int type)
{
	struct un_socket *socket = zalloc(sizeof(struct un_socket));
	if(!socket)
		return NULL;

	struct inode *vnode = (struct inode*) socket;
	memcpy(&vnode->i_fops, &un_ops, sizeof(struct file_ops));
	vnode->i_type = VFS_TYPE_UNIX_SOCK;
	socket->type = type;
	
	return (socket_t*) socket;
}
