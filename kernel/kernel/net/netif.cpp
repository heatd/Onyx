/*
 * Copyright (c) 2017 - 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
#include <assert.h>
#include <errno.h>
#include <net/if.h>
#include <net/if_arp.h>

#include <onyx/byteswap.h>
#include <onyx/dev.h>
#include <onyx/init.h>
#include <onyx/net/netif.h>
#include <onyx/net/netkernel.h>
#include <onyx/net/tcp.h>
#include <onyx/net/udp.h>
#include <onyx/softirq.h>
#include <onyx/spinlock.h>
#include <onyx/vector.h>

#include <uapi/ioctls.h>

static struct spinlock netif_list_lock = {};
cul::vector<netif *> netif_list;

unsigned int netif_ioctl(int request, void *argp, struct file *f)
{
    auto netif = static_cast<struct netif *>(f->f_ino->i_helper);
    assert(netif != nullptr);
    switch (request)
    {
        case SIOSETINET4: {
            struct if_config_inet *c = static_cast<if_config_inet *>(argp);

            struct if_config_inet i;
            if (copy_from_user(&i, c, sizeof(struct if_config_inet)) < 0)
                return -EFAULT;
            auto local = &netif->local_ip;
            memcpy(&local->sin_addr, &i.address, sizeof(struct in_addr));
            return 0;
        }
        case SIOGETINET4: {
            struct if_config_inet *c = static_cast<if_config_inet *>(argp);
            auto local = &netif->local_ip;
            if (copy_to_user(&c->address, &local->sin_addr, sizeof(struct in_addr)) < 0)
                return -EFAULT;
            return 0;
        }
        case SIOADDINET6ADDR: {
            if_inet6_addr *c = static_cast<if_inet6_addr *>(argp);

            if_inet6_addr addr;

            if (copy_from_user(&addr, c, sizeof(*c)) < 0)
                return -EFAULT;

            return netif_add_v6_address(netif, addr);
        }
        case SIOGETINET6: {
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
        case SIOGETMAC: {
            if (copy_to_user(argp, &netif->mac_address, 6) < 0)
                return -EFAULT;
            return 0;
        }

        case SIOGETINDEX: {
            if (copy_to_user(argp, &netif->if_id, sizeof(netif->if_id)) < 0)
                return -EFAULT;
            return 0;
        }
    }

    return -ENOTTY;
}

atomic<uint32_t> next_if = 1;

const struct file_ops netif_fops = {.ioctl = netif_ioctl};

void netif_register_loopback_route4(struct netif *netif)
{
    struct inet4_route route;

    route.mask = htonl(0xff000000);
    route.dest = htonl(INADDR_LOOPBACK);
    route.dest &= route.mask;
    route.gateway = 0;
    route.nif = netif;
    route.metric = 1000;
    route.flags = INET4_ROUTE_FLAG_SCOPE_LOCAL;

    assert(ip::v4::add_route(route) == true);
}

void netif_register_loopback_route6(struct netif *netif)
{
    struct inet6_route route;

    route.mask = IN6ADDR_LOOPBACK_INIT;
    route.dest = IN6ADDR_LOOPBACK_INIT;

    route.gateway = IN6ADDR_ANY_INIT;
    route.nif = netif;
    route.metric = 1000;
    route.flags = INET4_ROUTE_FLAG_SCOPE_LOCAL;

    assert(ip::v6::add_route(route) == true);
}

void netif_register_if(struct netif *netif)
{
    INIT_LIST_HEAD(&netif->inet6_addr_list);

    assert(udp_init_netif(netif) == 0);

    assert(tcp_init_netif(netif) == 0);

    auto ex = dev_register_chardevs(0, 1, 0, &netif_fops, netif->name);
    if (ex.has_error())
        panic("netif_register_if failed");

    auto cdev = ex.value();
    cdev->private_ = netif;
    cdev->show(0660);

    netif->if_id = next_if++;

    spin_lock(&netif_list_lock);

    assert(netif_list.push_back(netif) != false);

    spin_unlock(&netif_list_lock);

    bool is_loopback = netif->flags & NETIF_LOOPBACK;

    if (is_loopback)
    {
        netif_register_loopback_route4(netif);
        netif_register_loopback_route6(netif);
    }
}

int netif_unregister_if(struct netif *netif)
{
    scoped_lock g{netif_list_lock};

    list_remove(&netif->list_node);

    return 0;
}

struct netif *netif_choose(void)
{
    /* TODO: Netif refcounting would be bery noice */
    scoped_lock g{netif_list_lock};

    for (auto n : netif_list)
    {
        if (n->flags & NETIF_LINKUP && !(n->flags & NETIF_LOOPBACK))
        {
            return n;
        }
    }

    return NULL;
}

netif *netif_from_if(uint32_t oif)
{
    if (!oif)
        return nullptr;

    scoped_lock g{netif_list_lock};

    for (auto &c : netif_list)
    {
        if (c->if_id == oif)
            return c;
    }

    return nullptr;
}

netif *netif_get_from_addr(const inet_sock_address &s, int domain)
{
    scoped_lock g{netif_list_lock};

    // printk("trying to find %x\n", in->sin_addr.s_addr);

    for (auto n : netif_list)
    {
        // printk("local %x\n", n->local_ip.sin_addr.s_addr);
        if (domain == AF_INET && n->local_ip.sin_addr.s_addr == s.in4.s_addr)
        {
            return n;
        }

        if (domain == AF_INET6 && netif_find_v6_address(n, s.in6))
        {
            return n;
        }
    }

    return nullptr;
}

cul::vector<netif *> &netif_lock_and_get_list(void)
{
    spin_lock(&netif_list_lock);

    return netif_list;
}

void netif_unlock_list(void)
{
    spin_unlock(&netif_list_lock);
}

int netif_send_packet(netif *netif, packetbuf *buf)
{
    assert(netif != nullptr);
    if (netif->sendpacket)
        return netif->sendpacket(buf, netif);
    return -ENODEV;
}

void netif_get_ipv4_addr(struct sockaddr_in *s, struct netif *netif)
{
    memcpy(&s, &netif->local_ip, sizeof(struct sockaddr));
}

netif *netif_from_name(const char *name)
{
    scoped_lock g{netif_list_lock};

    // printk("trying to find %x\n", in->sin_addr.s_addr);

    for (auto n : netif_list)
    {
        // printk("local %x\n", n->local_ip.sin_addr.s_addr);
        if (!strcmp(n->name, name))
        {
            return n;
        }
    }

    return nullptr;
}

struct rx_queue_percpu
{
    struct list_head to_rx_list;
    struct spinlock lock;
};

PER_CPU_VAR(rx_queue_percpu rx_queue);

static void init_rx_queues(unsigned int cpu)
{
    auto q = get_per_cpu_ptr_any(rx_queue, cpu);
    spinlock_init(&q->lock);
    INIT_LIST_HEAD(&q->to_rx_list);
}

INIT_LEVEL_CORE_PERCPU_CTOR(init_rx_queues);

void netif_signal_rx(netif *nif)
{
    unsigned int flags, og_flags;

    do
    {
        flags = nif->flags;
        og_flags = flags;

        flags |= NETIF_HAS_RX_AVAILABLE;

        if (og_flags & NETIF_DOING_RX_POLL)
            flags |= NETIF_MISSED_RX;

    } while (!__atomic_compare_exchange_n(&nif->flags, &og_flags, flags, false, __ATOMIC_ACQUIRE,
                                          __ATOMIC_RELAXED));

    if (og_flags & NETIF_HAS_RX_AVAILABLE)
        return;

    auto queue = get_per_cpu_ptr(rx_queue);

    unsigned long cpu_flags = spin_lock_irqsave(&queue->lock);

    list_add_tail(&nif->rx_queue_node, &queue->to_rx_list);

    spin_unlock_irqrestore(&queue->lock, cpu_flags);

    softirq_raise(softirq_vector::SOFTIRQ_VECTOR_NETRX);
}

void netif_do_rxpoll(netif *nif)
{
    __atomic_or_fetch(&nif->flags, NETIF_DOING_RX_POLL, __ATOMIC_RELAXED);

    while (true)
    {
        nif->poll_rx(nif);

        unsigned int flags, og_flags;

        do
        {
            og_flags = flags = nif->flags;

            if (!(og_flags & NETIF_MISSED_RX))
            {
                nif->rx_end(nif);
                flags &= ~(NETIF_HAS_RX_AVAILABLE | NETIF_DOING_RX_POLL);
            }

            flags &= ~NETIF_MISSED_RX;

        } while (!__atomic_compare_exchange_n(&nif->flags, &og_flags, flags, false,
                                              __ATOMIC_ACQUIRE, __ATOMIC_RELAXED));

        if (!(flags & NETIF_DOING_RX_POLL))
            break;
    }
}

int netif_do_rx()
{
    auto queue = get_per_cpu_ptr(rx_queue);

    scoped_lock g{queue->lock};

    list_for_every (&queue->to_rx_list)
    {
        netif *n = container_of(l, netif, rx_queue_node);

        netif_do_rxpoll(n);
    }

    list_reset(&queue->to_rx_list);

    return 0;
}

int netif_process_pbuf(netif *nif, packetbuf *buf)
{
    return nif->dll_ops->rx_packet(nif, buf);
}

int netif_add_v6_address(netif *nif, const if_inet6_addr &addr_)
{
    if (addr_.flags & ~INET6_ADDR_DEFINED_MASK)
        return -EINVAL;

    auto addr = new netif_inet6_addr;
    if (!addr)
        return -ENOMEM;

    addr->address = addr_.address;
    addr->flags = addr_.flags;
    addr->prefix_len = addr_.prefix_len;

    scoped_rwslock<rw_lock::write> g{nif->inet6_addr_list_lock};

    list_add_tail(&addr->list_node, &nif->inet6_addr_list);

    return 0;
}

in6_addr netif_get_v6_address(netif *nif, uint16_t flags)
{
    scoped_rwslock<rw_lock::read> g{nif->inet6_addr_list_lock};

    list_for_every (&nif->inet6_addr_list)
    {
        const netif_inet6_addr *addr = container_of(l, netif_inet6_addr, list_node);

        if (addr->flags & flags)
        {
            return addr->address;
        }
    }

    return {};
}

int netif_remove_v6_address(netif *nif, const in6_addr &addr)
{
    scoped_rwslock<rw_lock::read> g{nif->inet6_addr_list_lock};

    list_for_every (&nif->inet6_addr_list)
    {
        netif_inet6_addr *a = container_of(l, netif_inet6_addr, list_node);

        if (a->address == addr)
        {
            list_remove(&a->list_node);
            return 0;
        }
    }

    return -ENOENT;
}

bool netif_find_v6_address(netif *nif, const in6_addr &addr)
{
    scoped_rwslock<rw_lock::read> g{nif->inet6_addr_list_lock};

    list_for_every (&nif->inet6_addr_list)
    {
        netif_inet6_addr *a = container_of(l, netif_inet6_addr, list_node);

        if (a->address == addr)
        {
            return true;
        }
    }

    return false;
}

class netif_table_nk : public netkernel::netkernel_object
{
public:
    netif_table_nk() : netkernel::netkernel_object{"netif_table"}
    {
    }
    expected<netkernel_hdr *, int> serve_request(netkernel_hdr *hdr) override
    {
        if (hdr->msg_type != NETKERNEL_MSG_NETIF_GET_NETIFS)
            return unexpected<int>{-ENXIO};

        cul::vector<netkernel_nif_interface> interface_response;
        const auto &interfaces = netif_lock_and_get_list();

        for (const auto &nif : interfaces)
        {
            netkernel_nif_interface i;
            i.if_index = nif->if_id;
            strcpy(i.if_name, nif->name);
            i.if_mtu = nif->mtu;
            i.if_flags = 0;

            if (nif->flags & NETIF_LINKUP)
                i.if_flags |= IFF_UP;
            if (nif->flags & NETIF_LOOPBACK)
                i.if_flags |= IFF_LOOPBACK;

            // We're only supporting loopback and ethernet for now
            if (nif->flags & NETIF_LOOPBACK)
            {
                i.if_hwaddr.sa_family = ARPHRD_LOOPBACK;
                i.if_brdaddr.sa_family = ARPHRD_LOOPBACK;
            }
            else
            {
                i.if_hwaddr.sa_family = ARPHRD_ETHER;
                i.if_brdaddr.sa_family = ARPHRD_ETHER;
            }

            for (int j = 0; j < 6; j++)
            {
                i.if_hwaddr.sa_data[j] = nif->mac_address[j];
            }

            for (int j = 0; j < 6; j++)
            {
                // TODO: Support other broadcast addresses?
                i.if_brdaddr.sa_data[j] = 0xff;
            }

            if (!interface_response.push_back(i))
            {
                netif_unlock_list();
                return unexpected<int>{-ENOMEM};
            }
        }

        netif_unlock_list();

        auto buf_size = sizeof(netkernel_get_nifs_response) +
                        interface_response.size() * sizeof(netkernel_nif_interface);
        netkernel_get_nifs_response *header = (netkernel_get_nifs_response *) malloc(buf_size);
        if (!header)
            return unexpected<int>{-ENOMEM};

        header->nr_ifs = interface_response.size();
        memcpy(header + 1, interface_response.begin(),
               interface_response.size() * sizeof(netkernel_nif_interface));

        header->hdr.msg_type = NETKERNEL_MSG_NETIF_GET_NETIFS;
        header->hdr.flags = 0;
        header->hdr.size = buf_size;

        return &header->hdr;
    }
};

void netif_init_netkernel()
{
    auto root = netkernel::open({"", 0});

    auto nif_member = make_shared<netkernel::netkernel_object>("netif");

    assert(nif_member != nullptr);

    nif_member->set_flags(NETKERNEL_OBJECT_PATH_ELEMENT);

    assert(root->add_child(nif_member) == true);

    auto nt = make_shared<netif_table_nk>();
    assert(nt != nullptr);

    auto generic_nt = cast<netkernel::netkernel_object, netif_table_nk>(nt);

    assert(nif_member->add_child(generic_nt));
}

INIT_LEVEL_CORE_KERNEL_ENTRY(netif_init_netkernel);
