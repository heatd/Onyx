/*
* Copyright (c) 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <assert.h>
#include <errno.h>

#include <onyx/netif.h>
#include <onyx/spinlock.h>
#include <onyx/dev.h>
#include <onyx/udp.h>
#include <onyx/tcp.h>

#include <sys/ioctl.h>

static struct spinlock netif_list_lock = {0};
struct netif *netif_list = NULL;
unsigned int netif_ioctl(int request, void *argp, struct inode* this)
{
	struct netif *netif = this->i_helper;
	assert(netif);
	switch(request)
	{
		case SIOSETINET4:
		{
			struct if_config_inet *c = argp;
			struct if_config_inet i;
			if(copy_from_user(&i, c, sizeof(struct if_config_inet)) < 0)
				return -EFAULT;
			struct sockaddr_in *local = (struct sockaddr_in*) &netif->local_ip;
			memcpy(&local->sin_addr, &i.address, sizeof(struct in_addr));
			struct sockaddr_in *router = (struct sockaddr_in*) &netif->router_ip;
			memcpy(&router->sin_addr, &i.router, sizeof(struct in_addr));
			return 0;
		}
		case SIOGETINET4:
		{
			struct if_config_inet *c = argp;
			struct sockaddr_in *local = (struct sockaddr_in*) &netif->local_ip;
			struct sockaddr_in *router = (struct sockaddr_in*) &netif->router_ip;
			if(copy_to_user(&c->address, &local->sin_addr, sizeof(struct in_addr)) < 0)
				return -EFAULT;
			if(copy_to_user(&c->router, &router->sin_addr, sizeof(struct in_addr)) < 0)
				return -EFAULT;
			return 0;
		}
		case SIOSETINET6:
		{
			struct if_config_inet *c = argp;
			struct sockaddr_in *local = (struct sockaddr_in*) &netif->local_ip;
			struct sockaddr_in *router = (struct sockaddr_in*) &netif->router_ip;
			if(copy_to_user(&local->sin_addr, &c->address, sizeof(struct in6_addr)) <0)
				return -EFAULT;
			if(copy_to_user(&router->sin_addr, &c->router, sizeof(struct in6_addr)) < 0)
				return -EFAULT;
			return 0;
		}
		case SIOGETINET6:
		{
			struct if_config_inet6 *c = argp;
			struct sockaddr_in6 *local = (struct sockaddr_in6*) &netif->local_ip;
			struct sockaddr_in6 *router = (struct sockaddr_in6*) &netif->router_ip;
			if(copy_to_user(&c->address, &local->sin6_addr, sizeof(struct in6_addr)) < 0)
				return -EFAULT;
			if(copy_to_user(&c->router, &router->sin6_addr, sizeof(struct in6_addr)) < 0)
				return -EFAULT;
			return 0;
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
	
	struct dev *d = dev_register(0, 0, (char*) netif->name);
	if(!d)
		return;

	d->priv = netif;

	d->fops.ioctl = netif_ioctl;

	device_show(d, DEVICE_NO_PATH, 0666);
	
	spin_lock(&netif_list_lock);
	
	if(!netif_list)
	{
		netif_list = netif;
	}
	else
	{
		struct netif *n = netif_list;
		while(n->next) n = n->next;
		n->next = netif;
	}

	spin_unlock(&netif_list_lock);
}

int netif_unregister_if(struct netif *netif)
{
	spin_lock(&netif_list_lock);
	if(netif_list == netif)
	{
		netif_list = netif->next;
		spin_unlock(&netif_list_lock);
		return 0;
	}
	else
	{
		struct netif *n = netif_list;
		while(n)
		{
			if(n->next == netif)
			{
				n->next = netif->next;
				spin_unlock(&netif_list_lock);
				return 0;
			}
			n = n->next;
		}
	}

	spin_unlock(&netif_list_lock);

	return -1;
}

struct netif *netif_choose(void)
{
	for(struct netif *n = netif_list; n; n = n->next)
	{
		if(n->flags & NETIF_LINKUP)
			return n;
	}

	return NULL;
}

int netif_send_packet(struct netif *netif, const void *buffer, uint16_t size)
{
	assert(netif);
	if(netif->sendpacket)
		return netif->sendpacket(buffer, size, netif);
	return errno = ENODEV, -1;
}

void netif_get_ipv4_addr(struct sockaddr_in *s, struct netif *netif)
{
	memcpy(&s, &netif->local_ip, sizeof(struct sockaddr));
}
