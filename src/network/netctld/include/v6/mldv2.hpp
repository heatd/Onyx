/*
* Copyright (c) 2020 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#pragma once
#include <cstdint>

#include <netinet/ip6.h>
#include <netinet/icmp6.h>

/* Sauce: https://tools.ietf.org/html/rfc3810#page-13 */

#define MLDV2_REPORT_MSG      143

#define MCAST_MODE_IS_INCLUDE      1
#define MCAST_MODE_IS_EXCLUDE      2
#define MCAST_CHANGE_TO_INCLUDE    3
#define MCAST_CHANGE_TO_EXCLUDE    4

struct multicast_address_record
{
	/* See above */
	std::uint8_t type;

	/* In 32-bit words */
	std::uint8_t aux_data_len;

	/* How many source addresses are present in this record */
	std::uint16_t nr_sources;

	in6_addr mcast_address;

	in6_addr sources[0];
};

struct mldv2_report
{
	/* The lower 16-bits of the icmpv6 header hold the number of mcast address records */
	struct icmp6_hdr header;

	struct multicast_address_record records[0];
};

/* The number of sources doesn't need to be constant between records but we'll do it
 * like this for simplicity
 */
constexpr size_t mldv2_report_size(unsigned int nr_records, unsigned int sources_per_record)
{
	return sizeof(mldv2_report) + (sizeof(multicast_address_record) * nr_records) +
           sources_per_record * sizeof(in6_addr) * nr_records;
}
