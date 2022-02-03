/*
 * Copyright (c) 2020 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 */

#include <onyx/init.h>
#include <onyx/net/ip.h>
#include <onyx/net/netkernel.h>

#define INET4_VALID_ROUTE_FLAGS INET4_ROUTE_FLAG_GATEWAY

static bool check_for_null_term(char *buf, size_t size)
{
    while (size--)
    {
        if (*buf == '\0')
            return true;
        buf++;
    }

    return false;
}

class ipv4_route_table_nk : public netkernel::netkernel_object
{
public:
    ipv4_route_table_nk() : netkernel::netkernel_object{"rt"}
    {
    }
    expected<netkernel_hdr *, int> serve_request(netkernel_hdr *hdr) override
    {
        if (hdr->msg_type != NETKERNEL_MSG_ROUTE4_ADD)
            return unexpected<int>{-ENXIO};

        netkernel_route4_add *ra = (netkernel_route4_add *) hdr;

        if (ra->hdr.size != sizeof(*ra))
            return unexpected<int>{-ENXIO};

        inet4_route rt;
        rt.dest = ra->dest.s_addr;
        rt.mask = ra->mask.s_addr;
        rt.metric = ra->metric;
        rt.flags = ra->flags;

        if (rt.flags & ~INET4_VALID_ROUTE_FLAGS)
            return unexpected<int>{-EINVAL};

        if (!check_for_null_term(ra->iface, sizeof(ra->iface)))
            return unexpected<int>{-EINVAL};

        rt.nif = netif_from_name(ra->iface);

        if (!rt.nif)
        {
            return unexpected<int>{-EINVAL};
        }

        rt.gateway = ra->gateway.s_addr;

        if (!ip::v4::add_route(rt))
            return unexpected<int>{-ENOMEM};

        netkernel_error *h = new netkernel_error{};
        if (!h)
            return unexpected<int>{-ENOMEM};

        memset(h, 0, sizeof(*h));
        h->hdr.msg_type = NETKERNEL_MSG_ERROR;
        h->hdr.size = sizeof(*h);
        h->error = 0;

        return (netkernel_hdr *) h;
    }
};

void ipv4_init_netkernel()
{
    /* TODO: Add helpers */
    auto root = netkernel::open({"", 0});

    auto ipv4_member = make_shared<netkernel::netkernel_object>("ipv4");

    assert(ipv4_member != nullptr);

    ipv4_member->set_flags(NETKERNEL_OBJECT_PATH_ELEMENT);

    assert(root->add_child(ipv4_member) == true);

    auto rt = make_shared<ipv4_route_table_nk>();
    assert(rt != nullptr);

    auto generic_rt = cast<netkernel::netkernel_object, ipv4_route_table_nk>(rt);

    assert(ipv4_member->add_child(generic_rt));
}

INIT_LEVEL_CORE_KERNEL_ENTRY(ipv4_init_netkernel);
