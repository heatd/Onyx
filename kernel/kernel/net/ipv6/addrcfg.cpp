/*
* Copyright (c) 2020 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#include <onyx/net/ipv6.h>
#include <onyx/net/icmpv6.h>

namespace ip
{

namespace v6
{


int netif_addrcfg(netif *nif, const in6_addr& if_id)
{
	inet_route r;
	r.src_addr.in6 = {};
	r.nif = nif;
	r.dst_hw = nullptr;
	r.dst_addr.in6 = IN6ADDR_ALL_ROUTERS;


	
	icmpv6::send_data sdata{ICMPV6_ROUTER_SOLICIT, 0, r};
	auto slc = cul::slice<unsigned char>{nullptr, 0};

	icmpv6::send_packet(sdata, slc);

	return 0;
}

}

}
