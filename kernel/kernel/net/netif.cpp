/*
* Copyright (c) 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <assert.h>
#include <errno.h>

#include <onyx/net/netif.h>
#include <onyx/spinlock.h>
#include <onyx/dev.h>
#include <onyx/net/udp.h>
#include <onyx/net/tcp.h>
#include <onyx/byteswap.h>
#include <onyx/net/sockets_info.hpp>

#include <sys/ioctl.h>

static struct spinlock netif_list_lock = {0};
struct list_head netif_list = LIST_HEAD_INIT(netif_list);

unsigned int netif_ioctl(int request, void *argp, struct file* f)
{
	auto netif = static_cast<struct netif *>(f->f_ino->i_helper);
	assert(netif != nullptr);
	switch(request)
	{
		case SIOSETINET4:
		{
			struct if_config_inet *c = static_cast<if_config_inet *>(argp);

			struct if_config_inet i;
			if(copy_from_user(&i, c, sizeof(struct if_config_inet)) < 0)
				return -EFAULT;
			auto local = &netif->local_ip;
			memcpy(&local->sin_addr, &i.address, sizeof(struct in_addr));
			return 0;
		}
		case SIOGETINET4:
		{
			struct if_config_inet *c = static_cast<if_config_inet *>(argp);
			auto local = &netif->local_ip;
			if(copy_to_user(&c->address, &local->sin_addr, sizeof(struct in_addr)) < 0)
				return -EFAULT;
			return 0;
		}
		case SIOSETINET6:
		{
			return -ENOSYS;
#if 0
			struct if_config_inet6 *c = static_cast<if_config_inet6 *>(argp);
			auto local = &netif->local_ip;
			auto router = &netif->router_ip;
			if(copy_to_user(&local->sin_addr, &c->address, sizeof(struct in6_addr)) <0)
				return -EFAULT;
			if(copy_to_user(&router->sin_addr, &c->router, sizeof(struct in6_addr)) < 0)
				return -EFAULT;
			return 0;
#endif
		}
		case SIOGETINET6:
		{
			return -ENOSYS;
#if 0
			struct if_config_inet6 *c = static_cast<if_config_inet6 *>(argp);
			auto local = &netif->local_ip;
			auto router = &netif->router_ip;
			if(copy_to_user(&c->address, &local->sin_addr, sizeof(struct in6_addr)) < 0)
				return -EFAULT;
			if(copy_to_user(&c->router, &router->sin_addr, sizeof(struct in6_addr)) < 0)
				return -EFAULT;
			return 0;
#endif
		}
		case SIOGETMAC:
		{
			if(copy_to_user(argp, &netif->mac_address, 6) < 0)
				return -EFAULT;
			return 0;
		}
	}
	return -ENOTTY;
}

void netif_register_if(struct netif *netif)
{
	assert(udp_init_netif(netif) == 0);
	
	assert(tcp_init_netif(netif) == 0);

	netif->sock_info = new sockets_info();
	
	assert(netif->sock_info != nullptr);
	
	struct dev *d = dev_register(0, 0, (char*) netif->name);
	if(!d)
		return;

	d->priv = netif;

	d->fops.ioctl = netif_ioctl;

	device_show(d, DEVICE_NO_PATH, 0666);
	
	spin_lock(&netif_list_lock);
	
	list_add_tail(&netif->list_node, &netif_list);

	spin_unlock(&netif_list_lock);

	bool is_loopback = netif->flags & NETIF_LOOPBACK;

	struct inet4_route route;
	
	route.mask = is_loopback ? htonl(0xff000000) : 0;
	route.dest = is_loopback ? htonl(INADDR_LOOPBACK) : 0;
	route.dest &= route.mask;
	route.gateway = 0;
	route.nif = netif;
	route.metric = is_loopback ? 1000 : 10;

	assert(ip::v4::add_route(route) == true);
}

int netif_unregister_if(struct netif *netif)
{
	spin_lock(&netif_list_lock);
	
	list_remove(&netif->list_node);

	spin_unlock(&netif_list_lock);

	return 0;
}

struct netif *netif_choose(void)
{
	/* TODO: Netif refcounting would be bery noice */
	spin_lock(&netif_list_lock);

	list_for_every(&netif_list)
	{
		netif *n = container_of(l, netif, list_node);
		if(n->flags & NETIF_LINKUP && !(n->flags & NETIF_LOOPBACK))
		{
			spin_unlock(&netif_list_lock);
			return n;
		}
	}

	spin_unlock(&netif_list_lock);

	return NULL;
}

netif *netif_get_from_addr(const inet_sock_address& s, int domain)
{
	spin_lock(&netif_list_lock);

	//printk("trying to find %x\n", in->sin_addr.s_addr);

	list_for_every(&netif_list)
	{
		netif *n = container_of(l, netif, list_node);
		//printk("local %x\n", n->local_ip.sin_addr.s_addr);
		if(domain == AF_INET && n->local_ip.sin_addr.s_addr == s.in4.s_addr)
		{
			spin_unlock(&netif_list_lock);
			return n;
		}
	}

	spin_unlock(&netif_list_lock);

	return nullptr;
}

struct list_head *netif_lock_and_get_list(void)
{
	spin_lock(&netif_list_lock);

	return &netif_list;
}

void netif_unlock_list(void)
{
	spin_unlock(&netif_list_lock);
}

int netif_send_packet(netif *netif, packetbuf *buf)
{
	assert(netif != nullptr);
	if(netif->sendpacket)
		return netif->sendpacket(buf, netif);
	return -ENODEV;
}

void netif_get_ipv4_addr(struct sockaddr_in *s, struct netif *netif)
{
	memcpy(&s, &netif->local_ip, sizeof(struct sockaddr));
}

/* TODO: Use range locks for increased efficiency, instead of having a big
 * lock like we have right now
 */

void netif_lock_socks(const socket_id& id, netif *nif)
{
	spin_lock(&nif->sock_info->lock);
}

void netif_unlock_socks(const socket_id& id, netif *nif)
{
	spin_unlock(&nif->sock_info->lock);
}

void netif_print_open_sockets(netif *nif);

inet_socket *netif_get_socket(const socket_id& id, netif *nif, unsigned int flags)
{
	auto socket_info = nif->sock_info;
	auto hash = inet_socket::make_hash_from_id(id);
	bool unlocked = flags & GET_SOCKET_UNLOCKED;

	if(!unlocked)
		netif_lock_socks(id, nif);

	/* Alright, so this is the standard hashtable thing - hash the socket_id,
	 * get the iterators, and then iterate through the list and compare the
	 * socket_id with the socket's internal id. This should be pretty efficient except for the
	 * big old lock that we should replace with ranged-locks(each lock locking a part of the hashtable).
	 */

	auto begin = socket_info->socket_hashtable.get_hash_list_begin(hash);
	auto end = socket_info->socket_hashtable.get_hash_list_end(hash);
	inet_socket *ret = nullptr;

	while(begin != end)
	{
		auto sock = *begin;
		if(sock->is_id(id, flags))
		{
			ret = sock;
			break;
		}

		begin++;
	}

	/* GET_SOCKET_CHECK_EXISTENCE is very useful for operations like bind,
	 * as to avoid two extra atomic operations.
	 */

	if(ret && !(flags & GET_SOCKET_CHECK_EXISTENCE))
		ret->ref();

	if(!unlocked)
		netif_unlock_socks(id, nif);

	return ret;
}

bool netif_add_socket(inet_socket *sock, netif *nif, unsigned int flags)
{
	bool unlocked = flags & ADD_SOCKET_UNLOCKED;

	const socket_id id(sock->proto, sock->domain, sock->src_addr, sock->dest_addr);

	if(!unlocked)
		netif_lock_socks(id, nif);

	bool success = nif->sock_info->socket_hashtable.add_element(sock);

	if(!unlocked)
		netif_unlock_socks(id, nif);

	return success;
}

bool netif_remove_socket(inet_socket *sock, netif *nif, unsigned int flags)
{
	bool unlocked = flags & REMOVE_SOCKET_UNLOCKED;

	const socket_id id(sock->proto, sock->domain, sock->src_addr, sock->dest_addr);

	if(!unlocked)
		netif_lock_socks(id, nif);

	bool success = nif->sock_info->socket_hashtable.remove_element(sock);

	if(!unlocked)
		netif_unlock_socks(id, nif);
	
	return success;
}

void netif_print_open_sockets(netif *nif)
{
	auto sinfo = nif->sock_info;
	
	for(size_t i = 0; i < 512; i++)
	{
		auto list = sinfo->socket_hashtable.get_hashtable(i);

		for(auto &socket : list)
		{		
			if(socket->domain == AF_INET)
			{
				const auto& inet_addr = socket->src_addr;
				const auto& inet_daddr = socket->dest_addr;
				printk("[%lu] Socket bound ip %x port %u - ", i, inet_addr.in4.s_addr, ntohs(inet_addr.port));
				printk("Connected to %x, port %u - ", inet_daddr.in4.s_addr, ntohs(inet_daddr.port));
				printk("protocol %u - hash %x\n", socket->proto, inet_socket::make_hash(socket));
			}
			else
				printk("unknown socket of domain %d, %p\n", socket->domain, socket);
		}
	}
}

netif *netif_from_name(const char *name)
{
	spin_lock(&netif_list_lock);

	//printk("trying to find %x\n", in->sin_addr.s_addr);

	list_for_every(&netif_list)
	{
		netif *n = container_of(l, netif, list_node);
		//printk("local %x\n", n->local_ip.sin_addr.s_addr);
		if(!strcmp(n->name, name))
		{
			spin_unlock(&netif_list_lock);
			return n;
		}
	}

	spin_unlock(&netif_list_lock);

	return nullptr;
}
