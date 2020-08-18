/*
* Copyright (c) 2020 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#include <onyx/init.h>

#include <onyx/net/netkernel.h>
#include <onyx/net/ip.h>
#include <onyx/net/ipv6.h>

#define INET4_VALID_ROUTE_FLAGS          INET4_ROUTE_FLAG_GATEWAY

static bool check_for_null_term(char *buf, size_t size)
{
	while(size--)
	{
		if(*buf == '\0')
			return true;
		buf++;
	}

	return false;
}

class ipv6_route_table_nk : public netkernel::netkernel_object
{
public:
	ipv6_route_table_nk() : netkernel::netkernel_object{"rt"} {}
	expected<netkernel_hdr *, int> serve_request(netkernel_hdr *hdr) override
	{
		if(hdr->msg_type != NETKERNEL_MSG_ROUTE6_ADD)
			return unexpected<int>{-ENXIO};
		
		netkernel_route6_add *ra = (netkernel_route6_add *) hdr;

		if(ra->hdr.size != sizeof(*ra))
			return unexpected<int>{-ENXIO};
		
		inet6_route rt;
		rt.dest = ra->dest;
		rt.mask = ra->mask;
		rt.metric = ra->metric;
		rt.flags = ra->flags;

		if(rt.flags & ~INET4_VALID_ROUTE_FLAGS)
			return unexpected<int>{-EINVAL};

		if(!check_for_null_term(ra->iface, sizeof(ra->iface)))
			return unexpected<int>{-EINVAL};

		rt.nif = netif_from_name(ra->iface);

		if(!rt.nif)
		{
			return unexpected<int>{-EINVAL};
		}

		rt.gateway = ra->gateway;

		if(!ip::v6::add_route(rt))
			return unexpected<int>{-ENOMEM};
	
		netkernel_error *h = new netkernel_error{};
		if(!h)
			return unexpected<int>{-ENOMEM};

		memset(h, 0, sizeof(*h));
		h->hdr.msg_type = NETKERNEL_MSG_ERROR;
		h->hdr.size = sizeof(*h);
		h->error = 0;

		return (netkernel_hdr *) h;
	}
};

class ipv6_addrcfg : public netkernel::netkernel_object
{
public:
	ipv6_addrcfg() : netkernel::netkernel_object{"slaac"} {}
	expected<netkernel_hdr *, int> serve_request(netkernel_hdr *hdr) override
	{
		if(hdr->msg_type != NETKERNEL_MSG_IPV6_ADDRCFG)
			return unexpected<int>{-ENXIO};
		
		netkernel_ipv6_addrcfg *cfg = (netkernel_ipv6_addrcfg *) hdr;

		if(cfg->hdr.size != sizeof(*cfg))
			return unexpected<int>{-ENXIO};
		
		if(!check_for_null_term(cfg->iface, sizeof(cfg->iface)))
			return unexpected<int>{-EINVAL};
		
		auto nif = netif_from_name(cfg->iface);
		if(!nif)
			return unexpected<int>{-EINVAL};

		int st = ip::v6::netif_addrcfg(nif, cfg->interface_id);

		netkernel_error *h = new netkernel_error{};
		if(!h)
			return unexpected<int>{-ENOMEM};

		memset(h, 0, sizeof(*h));
		h->hdr.msg_type = NETKERNEL_MSG_ERROR;
		h->hdr.size = sizeof(*h);
		h->error = st;

		return {(netkernel_hdr *) h};
	}
};

void ipv6_init_netkernel()
{
	/* TODO: Add helpers */
	auto root = netkernel::open({"", 0});

	auto ipv6_member = make_shared<netkernel::netkernel_object>("ipv6");

	assert(ipv6_member != nullptr);

	ipv6_member->set_flags(NETKERNEL_OBJECT_PATH_ELEMENT);

	assert(root->add_child(ipv6_member) == true);

	auto rt = make_shared<ipv6_route_table_nk>();
	assert(rt != nullptr);

	auto generic_rt = cast<netkernel::netkernel_object, ipv6_route_table_nk>(rt);

	assert(ipv6_member->add_child(generic_rt));

	auto addrcfg_ = make_shared<ipv6_addrcfg>();
	assert(addrcfg_ != nullptr);

	auto _ = cast<netkernel::netkernel_object, ipv6_addrcfg>(addrcfg_);
	assert(ipv6_member->add_child(_));
}

INIT_LEVEL_CORE_KERNEL_ENTRY(ipv6_init_netkernel);
