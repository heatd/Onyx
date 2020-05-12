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
#include <onyx/net/network.h>
#include <onyx/net/netif.h>
#include <onyx/compiler.h>
#include <onyx/utils.h>
#include <onyx/random.h>
#include <onyx/condvar.h>
#include <onyx/file.h>
#include <onyx/panic.h>

#include <netinet/in.h>

#include <sys/types.h>
#include <sys/un.h>

struct unix_packet
{
	const void *buffer;
	size_t size;
	size_t read;
	struct un_name *source;
	struct unix_packet *next;
};

struct un_socket : public socket
{
	struct spinlock socket_lock;
	struct unix_packet *packet_list;
	struct mutex packet_list_lock;
	struct cond packet_condvar;
	struct un_name *abstr_name;

	struct un_socket *dest;

	bool conn_reset;
};

struct un_name
{
	struct object object;
	char *address;
	size_t namelen;

	struct un_socket *bound_socket;
	struct un_name *next;
};

struct un_name *un_namespace_list = NULL;
struct spinlock un_namespace_list_lock;

struct un_name *un_find_name(char *address, size_t namelen);

static void __append_name(un_name *name)
{
	spin_lock(&un_namespace_list_lock);

	struct un_name **pp = &un_namespace_list;

	while(*pp)
		pp = &(*pp)->next;

	*pp = name;

	spin_unlock(&un_namespace_list_lock);
}

struct un_name *add_to_namespace(char *address, size_t namelen,
	struct un_socket *bound_socket)
{
	if(un_find_name(address, namelen))
	{
		spin_unlock(&un_namespace_list_lock);
		return errno = EADDRINUSE, nullptr;
	}

	char *newbuffer = nullptr;

	struct un_name *name = static_cast<un_name*>(zalloc(sizeof(*name)));
	if(!name)
		goto cleanup_and_die;
	
	newbuffer = static_cast<char *>(memdup(address, namelen));
	if(!newbuffer)
		goto cleanup_and_die;
		
	name->address = newbuffer;
	name->bound_socket = bound_socket;

	bound_socket->abstr_name = name;

	name->namelen = namelen;

	__append_name(name);

	return name;
cleanup_and_die:
	if(name)
	{
		if(newbuffer)	free(newbuffer);
		free(name);
	}

	return NULL;
}

/* Note: Leaves un_namespace_list_lock locked */
struct un_name *un_find_name(char *address, size_t namelen)
{
	spin_lock(&un_namespace_list_lock);

	for(struct un_name *name = un_namespace_list; name != NULL; name = name->next)
	{
		if(namelen != name->namelen)
			continue;
		if(!memcmp(name->address, address, namelen))
		{
			return name;
		}
	}

	spin_unlock(&un_namespace_list_lock);

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
		struct file *cwd = get_current_directory();

		struct file *inode = mknod_vfs(address, S_IFDIR | 0666, 0, get_fs_base(address, cwd));
		if(!inode)
			return -errno;

		panic("implement the rest");

		return 0;
	}
	else
	{
		if(!add_to_namespace(address, namelen, socket))
			return -errno;
	}
	
	return 0;
}

int un_bind(struct sockaddr *addr, socklen_t addrlen, struct socket *s)
{
	struct un_socket *socket = (struct un_socket*) s;
	if(socket->bound)
		return -EINVAL;

	if(addrlen > sizeof(struct sockaddr_un))
		return -EINVAL;
	
	struct sockaddr_un *un = (struct sockaddr_un *) addr;

	int st = un_do_bind(un, addrlen, socket);
	if(st == 0)
		socket->bound = true;
	return st;
}

int un_bind_ephemeral(struct un_socket *socket)
{
	struct sockaddr_un bind_addr = {0};
	socklen_t addrlen = sizeof(sa_family_t) + 20;
	bool failed = false;

	do
	{
		char buffer[20];
		buffer[0] = '\0';
		arc4random_buf(buffer + 1, 19);
		bind_addr.sun_family = AF_UNIX;
		memcpy(buffer, bind_addr.sun_path, 20);

	} while((failed = un_do_bind(&bind_addr, addrlen, socket) < 0) && errno == EADDRINUSE);

	if(failed)
		return -errno;
	else
	{
		socket->bound = true;
		return 0;
	}
}

int un_connect(struct sockaddr *addr, socklen_t addrlen, struct socket *s)
{
	struct un_socket *socket = (struct un_socket *) s;

	struct sockaddr_un *un = (struct sockaddr_un *) addr;
	char *address;
	size_t namelen;
	bool is_abstract;

	int status = 0;

	if(!socket->bound)
	{
		int st = un_bind_ephemeral(socket);
		if(st < 0)
			return st;
	}

	if((status = un_get_address(un, addrlen, &address, &namelen,
		&is_abstract)) < 0)
	{
		return status;
	}
	
	if(is_abstract)
	{
		struct un_name *name = un_find_name(address, namelen);
		if(!name)
		{
			return -EADDRNOTAVAIL;
		}

		name->bound_socket->ref();
		spin_unlock(&un_namespace_list_lock);

		socket->dest = name->bound_socket;
	}
	else
	{
		assert(is_abstract != true);
	}

	return 0;
}

ssize_t un_do_sendto(const void *buf, size_t len, struct un_socket *dest, struct un_socket *socket)
{
	assert(dest != NULL);

	struct unix_packet *packet = static_cast<unix_packet *>(malloc(sizeof(*packet)));
	if(!packet)
	{
		return -ENOMEM;
	}

	packet->buffer = memdup((void *) buf, len);
	if(!packet->buffer)
	{
		free(packet);
		return -ENOMEM;
	}

	packet->read = 0;
	packet->size = len;
	packet->next = NULL;
	packet->source = socket->abstr_name;

	spin_lock(&dest->socket_lock);

	mutex_lock(&dest->packet_list_lock);
	struct unix_packet **pp = &dest->packet_list;

	while(*pp)
		pp = &(*pp)->next;

	*pp = packet;

	condvar_signal(&dest->packet_condvar);

	mutex_unlock(&dest->packet_list_lock);
	spin_unlock(&dest->socket_lock);

	return len;
}

ssize_t un_sendto(const void *buf, size_t len, int flags,
	struct sockaddr *_addr, socklen_t addrlen, struct socket *s)
{
	struct sockaddr_un a = {};
	if(_addr)
	{
		if(addrlen > sizeof(struct sockaddr_un))
			return -EINVAL;
		if(copy_from_user(&a, _addr, addrlen) < 0)
			return -EFAULT;
	}

	struct sockaddr *addr = (struct sockaddr *) &a;
	struct un_socket *socket = (struct un_socket *) s;
	
	spin_lock(&socket->socket_lock);

	bool not_conn = !socket->dest;
	struct un_socket *dest = socket->dest;

	char *address;
	size_t namelen;
	bool is_abstract;
	bool has_to_unref = false;

	if(not_conn && !addr)
	{
		spin_unlock(&socket->socket_lock);
		return -ENOTCONN;
	}
	else if(not_conn)
	{
		int status = 0;
		if((status = un_get_address((struct sockaddr_un *) addr, addrlen, &address, &namelen,
			&is_abstract)) < 0)
		{
			spin_unlock(&socket->socket_lock);
			return status;
		}

		struct un_name *name = un_find_name(address, namelen);
		if(!name)
		{
			spin_unlock(&socket->socket_lock);
			return -EDESTADDRREQ;
		}

		dest = name->bound_socket;
		dest->ref();
		has_to_unref = true;
		spin_unlock(&un_namespace_list_lock);
	}
	
	if(!dest)
	{
		spin_unlock(&socket->socket_lock);
		return -EDESTADDRREQ;
	}

	if(dest->conn_reset)
	{
		socket->unref();
		spin_unlock(&socket->socket_lock);
		return -ECONNRESET;
	}


	ssize_t st = un_do_sendto(buf, len, dest, socket);
	spin_unlock(&socket->socket_lock);

	if(has_to_unref)
		socket->unref();

	return st;
}

void un_dispose_packet(struct unix_packet *packet)
{	
	free((void *) packet->buffer);
	free(packet);
}

ssize_t un_do_recvfrom(struct un_socket *socket, void *buf, size_t len,
		       int flags, struct sockaddr_un *addr, socklen_t *slen)
{
	mutex_lock(&socket->packet_list_lock);

	while(!socket->packet_list)
	{
		condvar_wait(&socket->packet_condvar, &socket->packet_list_lock);
	}

	struct unix_packet *packet = socket->packet_list;

	size_t to_read = min(len, packet->size);
	auto packet_ptr = static_cast<const char *>(packet->buffer) + packet->read;
	if(copy_to_user(buf, reinterpret_cast<const void *>(packet_ptr), to_read) < 0)
	{
		mutex_unlock(&socket->packet_list_lock);
		return errno = EFAULT, -1;
	}

	if(socket->type == SOCK_DGRAM)
		packet->read = packet->size;
	else
		packet->read += to_read;

	if(packet->source)
	{
		struct sockaddr_un un;
		un.sun_family = AF_UNIX;
		un.sun_path[0] = '\0';
		memcpy(&un.sun_path[1], packet->source->address, packet->source->namelen);
		*slen = sizeof(sa_family_t) + 1 + packet->source->namelen;

		memcpy(addr, &un, sizeof(struct sockaddr_un));
	}

	if(packet->read == packet->size)
	{
		socket->packet_list = packet->next;
		un_dispose_packet(packet);
	}

	mutex_unlock(&socket->packet_list_lock);

	return (ssize_t) to_read;
}

ssize_t un_recvfrom(void *buf, size_t len, int flags, struct sockaddr *addr, 
		socklen_t *slen, struct socket *s)
{
	struct un_socket *socket = (struct un_socket *) s;
	struct sockaddr_un kaddr = {0};
	socklen_t addrlen = sizeof(struct sockaddr_un);
	socklen_t kaddrlen;

	if(addr != NULL && slen == NULL)
		return errno = EINVAL, -1;
	
	if(addr == NULL && slen != NULL)
		return errno = EINVAL, -1;

	if(slen)
	{
		if(copy_from_user(&addrlen, slen, sizeof(socklen_t)) < 0)
			return errno = EFAULT, -1;
	}

	ssize_t st = un_do_recvfrom(socket, buf, len, flags, &kaddr, &kaddrlen);

	if(st < 0)
	{
		return errno = -st, -1;
	}

	addrlen = min(addrlen, kaddrlen);

	if(kaddr.sun_family != AF_UNIX)
		return st;

	if(addr)
	{
		if(copy_to_user(addr, &kaddr, addrlen) < 0)
			return errno = EFAULT, -1;
	}

	if(slen)
	{
		if(copy_to_user(slen, &addrlen, sizeof(socklen_t)) < 0)
			return errno = EFAULT, -1;
	}

	return st;
}

static struct sock_ops un_ops = 
{
	.bind = un_bind,
	.connect = un_connect,
	.sendto = un_sendto,
	.recvfrom = un_recvfrom,
};

void unix_socket_dtor(struct socket *socket)
{
	struct un_socket *un = (struct un_socket *) socket;
	if(un->abstr_name)	un->abstr_name->bound_socket = NULL;
}

struct socket *unix_create_socket(int type, int protocol)
{
	struct un_socket *socket = new un_socket();
	if(!socket)
		return NULL;

	mutex_init(&socket->packet_list_lock);
	socket->s_ops = &un_ops;
	socket->type = type;
	socket->dtor = unix_socket_dtor;

	return (struct socket *) socket;
}
