/*
* Copyright (c) 2020 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#include <cstdlib>
#include <cstring>
#include <cstdint>
#include "../uuid.h"

#define _POSIX_SOURCE

#include <time.h>
#include <sys/time.h>

struct uuid_format
{
	std::uint32_t time_low;
	std::uint16_t time_mid;
	std::uint16_t time_hi_and_version;
	std::uint8_t clk_seq_hi_and_res;
	std::uint8_t clk_seq_low;
	std::uint8_t node_id[6];
} __attribute__((packed));

union uuid_representation
{
	struct uuid_format format;
	uuid_t raw;
};

void uuid_generate_time(uuid_t out)
{
	uuid_generate_time_safe(out);
}

constexpr unsigned int version_shift = 4;
constexpr unsigned int version_mask = (0b1111 << version_shift);

static void set_version_and_variant(uuid_representation *uuid, unsigned int version, unsigned int variant)
{
	uuid->format.time_hi_and_version &= ~version_mask;
	uuid->format.time_hi_and_version = version << version_shift;
	(void) variant;
}

int uuid_generate_time_safe(uuid_t out)
{
	/* TODO: So, technically this would need to return a valid v1 uuid, 
	 * but currently it's impossible to get the mac address, etc from a socket.
	 * So we just generate a v4 one instead. Thankfully, on 64-bit systems
	 * we're able to fill the whole uuid, for now.
	 */
	struct timespec ts;
	if(clock_gettime(CLOCK_MONOTONIC, &ts) < 0)
		std::abort();

	ts.tv_sec *= 0x101010101010;
	ts.tv_nsec *= 0xabcabcabc78;

	auto off = 0;
	std::memcpy(&out[0], &ts.tv_sec, sizeof(ts.tv_sec));
	off += sizeof(ts.tv_sec);
	std::memcpy(&out[off], &ts.tv_nsec, sizeof(ts.tv_nsec));
	off += sizeof(ts.tv_nsec);

	set_version_and_variant(reinterpret_cast<uuid_representation*>(out), 4, 1);

	return 0;
}

void uuid_generate(uuid_t out);
void uuid_generate_random(uuid_t out);
