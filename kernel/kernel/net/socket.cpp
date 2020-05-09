/*
* Copyright (c) 2018 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <errno.h>

#include <onyx/file.h>
#include <onyx/utils.h>
#include <onyx/net/socket.h>
#include <onyx/net/ip.h>

struct socket *file_to_socket(struct file *f)
{
	return static_cast<struct socket *>(f->f_ino->i_helper);
}

/* Most of these default values don't make much sense, but we have them as placeholders */
int default_listen(struct socket *sock)
{
	(void) sock;
	return 0;
}

struct socket *default_accept(struct socket_conn_request *req, struct socket *sock)
{
	(void) sock;
	(void) req;
	return errno = EIO, nullptr;
}

int default_bind(struct sockaddr *addr, socklen_t addrlen, struct socket *sock)
{
	(void) addr;
	(void) addrlen;
	(void) sock;
	return -EIO;
}

int default_connect(struct sockaddr *addr, socklen_t addrlen, struct socket *sock)
{
	(void) addr;
	(void) addrlen;
	(void) sock;
	return -EIO;
}

ssize_t default_sendto(const void *buf, size_t len, int flags,
		struct sockaddr *addr, socklen_t addrlen, struct socket *sock)
{
	(void) buf;
	(void) len;
	(void) flags;
	(void) addr;
	(void) addrlen;
	(void) sock;
	return -EIO;
}

ssize_t default_recvfrom(void *buf, size_t len, int flags, struct sockaddr *addr, 
		socklen_t *slen, struct socket *sock)
{
	(void) buf;
	(void) len;
	(void) flags;
	(void) addr;
	(void) slen;
	(void) sock;
	return -EIO;
}

struct sock_ops default_s_ops =
{
	.listen = default_listen,
	.accept = default_accept,
	.bind = default_bind,
	.connect = default_connect,
	.sendto = default_sendto,
	.recvfrom = default_recvfrom
};

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

size_t socket_write(size_t offset, size_t len, void* buffer, struct file* file)
{
	struct socket *s = file_to_socket(file);

	return s->s_ops->sendto(buffer, len, 0, nullptr, 0, s);
}

void socket_close(struct inode *ino);

struct file_ops socket_ops = 
{
	.write = socket_write,
	.close = socket_close
};

struct file *get_socket_fd(int fd)
{
	struct file *desc = get_file_description(fd);
	if(!desc)
		return errno = EBADF, nullptr;

	if(desc->f_ino->i_fops->write != socket_write)
	{
		fd_put(desc);
		return errno = ENOTSOCK, nullptr;
	}

	return desc;
}

extern "C"
ssize_t sys_sendto(int sockfd, const void *buf, size_t len, int flags,
	struct sockaddr *addr, socklen_t addrlen)
{
	struct file *desc = get_socket_fd(sockfd);
	if(!desc)
		return -errno;

	struct socket *s = file_to_socket(desc);
	ssize_t ret = s->s_ops->sendto(buf, len, flags, addr, addrlen, s);

	fd_put(desc);
	return ret;
}

extern "C"
int sys_connect(int sockfd, const struct sockaddr *uaddr, socklen_t addrlen)
{
	sockaddr_storage addr;
	if(addrlen > sizeof(sockaddr_storage))
		return -EINVAL;

	if(copy_from_user(&addr, uaddr, addrlen) < 0)
		return -EFAULT;

	struct file *desc = get_socket_fd(sockfd);
	if(!desc)
		return -errno;
	
	int ret = -EINTR;
	struct socket *s = file_to_socket(desc);

	/* See the comment below in sys_bind for explanation */
	if(mutex_lock_interruptible(&s->connection_state_lock) < 0)
		goto out;

	ret = s->s_ops->connect((sockaddr *) &addr, addrlen, s);

	mutex_unlock(&s->connection_state_lock);
out:
	fd_put(desc);
	return ret;
}

extern "C"
int sys_bind(int sockfd, const struct sockaddr *uaddr, socklen_t addrlen)
{
	sockaddr_storage addr;
	if(addrlen > sizeof(sockaddr_storage))
		return -EINVAL;

	if(copy_from_user(&addr, uaddr, addrlen) < 0)
		return -EFAULT;

	struct file *desc = get_socket_fd(sockfd);
	if(!desc)
		return -errno;

	struct socket *s = file_to_socket(desc);
	int ret = -EINTR;

	/* We use mutex_lock_interruptible here as we can be held up for quite a
	 * big amount of time for things like TCP connect()s that are timing out.
	 */
	if(mutex_lock_interruptible(&s->connection_state_lock) < 0)
		goto out;

	ret = s->s_ops->bind((sockaddr *) &addr, addrlen, s);

	mutex_unlock(&s->connection_state_lock);

out:
	fd_put(desc);
	return ret;
}

extern "C"
ssize_t sys_recvfrom(int sockfd, void *buf, size_t len, int flags,
                     struct sockaddr *src_addr, socklen_t *addrlen)
{
	struct file *desc = get_socket_fd(sockfd);
	if(!desc)
		return -errno;

	struct socket *s = file_to_socket(desc);

	ssize_t ret = s->s_ops->recvfrom(buf, len, flags, src_addr, addrlen, s);
	
	fd_put(desc);
	return ret;
}

#define BACKLOG_FOR_LISTEN_0			16
const int backlog_limit = 4096;

bool sock_listening(struct socket *sock)
{
	return sock->backlog != 0;
}

extern "C"
int sys_listen(int sockfd, int backlog)
{
	int st = 0;
	struct file *f = get_socket_fd(sockfd);
	if(!f)
		return -errno;

	struct socket *sock = file_to_socket(f);

	if(sock->type != SOCK_DGRAM || sock->type != SOCK_SEQPACKET)
	{
		st = -EOPNOTSUPP;
		goto out;
	}

	/* POSIX specifies that if backlog = 0, we can (and should) set the backlog value
	 * to a implementation specified minimum
	 */

	if(backlog == 0)
	{
		backlog = BACKLOG_FOR_LISTEN_0;
	}

	/* We should also set a backlog limit to stop DDOS attacks, and clamp the value */
	if(backlog > backlog_limit)
		backlog = backlog_limit;
	
	if(mutex_lock_interruptible(&sock->connection_state_lock) < 0)
	{
		st = -EINTR;
		goto out;
	}

	/* Big note: the backlog value in the socket structure is used both to determine
	 * the backlog size **and** if the socket is in a listening state, with != 0 repre-
	 * senting that state.
	*/
	
	sock->backlog = backlog;

	if((st = sock->s_ops->listen(sock)) < 0)
	{
		/* Don't forget to reset the backlog to 0 to show that it's not in a
		 * listening state
		*/
		sock->backlog = 0;
		goto out2;
	}

out2:
	mutex_unlock(&sock->connection_state_lock);
out:
	fd_put(f);
	return st;
}

int check_af_support(int domain)
{
	switch(domain)
	{
		case AF_INET:
			return 0;
		case AF_UNIX:
			return 0;
		default:
			return -1;
	}
}

static const int type_mask = SOCK_DGRAM | SOCK_STREAM | SOCK_SEQPACKET;
static const int sock_flag_mask = ~type_mask;

int net_check_type_support(int type)
{
	(void) sock_flag_mask;
	return type & type_mask;
}

int net_autodetect_protocol(int type, int domain)
{
	switch(type & type_mask)
	{
		case SOCK_DGRAM:
		{
			if(domain == AF_UNIX)
				return PROTOCOL_UNIX;
			else if(domain == AF_INET)
				return PROTOCOL_UDP;
			else
				return -1;
		}
		case SOCK_RAW:
		{
			if(domain == AF_INET)
				return PROTOCOL_IPV4;
			else if(domain == AF_UNIX)
				return PROTOCOL_UNIX;
			return -1;
		}
		case SOCK_STREAM:
		{
			if(domain == AF_INET)
				return PROTOCOL_TCP;
			else
				return -1;
		}
	}

	return -1;
}

struct socket *unix_create_socket(int type, int protocol);

struct socket *socket_create(int domain, int type, int protocol)
{
	struct socket *socket = nullptr;
	switch(domain)
	{
		case AF_INET:
			socket = ipv4_create_socket(type, protocol);
			break;
		case AF_UNIX:
			socket = unix_create_socket(type, protocol);
			break;
		default:
			return errno = EAFNOSUPPORT, nullptr;
	}

	if(!socket)
		return nullptr;

	socket->type = type;
	socket->domain = domain;
	socket->proto = protocol;
	INIT_LIST_HEAD(&socket->conn_request_list);
	if(!socket->s_ops)
		socket->s_ops = &default_s_ops;
	socket_init(socket);

	return socket;
}

void socket_close(struct inode *ino)
{
	struct socket *s = static_cast<struct socket *>(ino->i_helper);

	socket_unref(s);
}

struct inode *socket_create_inode(struct socket *socket)
{
	struct inode *inode = inode_create(false);

	if(!inode)
		return nullptr;
	
	inode->i_fops = &socket_ops;

	inode->i_type = VFS_TYPE_UNIX_SOCK;
	inode->i_helper = socket;

	return inode;
}

extern "C"
int sys_socket(int domain, int type, int protocol)
{
	int dflags;
	dflags = O_RDWR;

	if(check_af_support(domain) < 0)
		return -EAFNOSUPPORT;

	if(net_check_type_support(type) < 0)
		return -EINVAL;

	if(protocol == 0)
	{
		/* If protocol == 0, auto-detect the proto */
		if((protocol = net_autodetect_protocol(type, domain)) < 0)
			return -EINVAL;
	}

	/* Create the socket */
	struct socket *socket = socket_create(domain, type, protocol);
	if(!socket)
		return -errno;
	
	struct inode *inode = socket_create_inode(socket);
	if(!inode)
		return -errno;

	struct file *f = inode_to_file(inode);
	if(!f)
	{
		close_vfs(inode);
		return -ENOMEM;
	}

	if(type & SOCK_CLOEXEC)
		dflags |= O_CLOEXEC;

	/* Open a file descriptor with the socket vnode */
	int fd = open_with_vnode(f, dflags);
	/* If we failed, close the socket and return */
	if(fd < 0)
		close_vfs(inode);
	fd_put(f);

	return fd;
}

/* TODO: Implement SOCK_NONBLOCK support */

#define ACCEPT4_VALID_FLAGS		(SOCK_CLOEXEC)		

struct socket_conn_request *dequeue_conn_request(struct socket *sock)
{
	spin_lock(&sock->conn_req_list_lock);

	assert(list_is_empty(&sock->conn_request_list) == false);
	struct list_head *first_elem = list_first_element(&sock->conn_request_list);

	list_remove(first_elem);

	spin_unlock(&sock->conn_req_list_lock);

	struct socket_conn_request *req = container_of(first_elem, struct socket_conn_request, list_node);

	return req;
}

extern "C"
int sys_accept4(int sockfd, struct sockaddr *addr, socklen_t *slen, int flags)
{
	int st = 0;
	if(flags & ~ACCEPT4_VALID_FLAGS)
		return -EINVAL;
	
	struct file *f = get_socket_fd(sockfd);
	if(!f)
		return -errno;
	
	struct socket *sock = file_to_socket(f);
	struct socket_conn_request *req = nullptr;
	struct socket *new_socket = nullptr;
	struct inode *inode = nullptr;
	struct file *newf = nullptr;
	int dflags = 0, fd = -1;

	if(mutex_lock_interruptible(&sock->connection_state_lock) < 0)
	{
		st = -EINTR;
		goto out_no_lock;
	}

	if(!sock_listening(sock))
	{
		st = -EINVAL;
		goto out;
	}

	if(sock->type != SOCK_STREAM)
	{
		st = -EOPNOTSUPP;
		goto out;
	}

	sem_wait(&sock->listener_sem);

	req = dequeue_conn_request(sock);

	new_socket = sock->s_ops->accept(req, sock);
	free(req);

	if(!new_socket)
	{
		st = -errno;
		goto out;
	}

	inode = socket_create_inode(new_socket);
	if(!inode)
	{
		socket_unref(new_socket);
		st = -errno;
		goto out;
	}

	newf = inode_to_file(inode);
	if(!newf)
	{
		close_vfs(inode);
		st = -errno;
		goto out;
	}

	if(flags & SOCK_CLOEXEC)
		dflags |= O_CLOEXEC;

	/* Open a file descriptor with the socket vnode */
	fd = open_with_vnode(newf, dflags);

	fd_put(newf);

	st = fd;
out:
	mutex_unlock(&sock->connection_state_lock);
out_no_lock:
	fd_put(f);
	return st;
}

extern "C"
int sys_accept(int sockfd, struct sockaddr *addr, socklen_t *slen)
{
	return sys_accept4(sockfd, addr, slen, 0);
}
