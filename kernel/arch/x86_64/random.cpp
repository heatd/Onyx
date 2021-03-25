/*
* Copyright (c) 2021 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#include <onyx/random.h>
#include <onyx/cpu.h>

namespace entropy
{

namespace platform
{

template <typename Type>
Type rdrand()
{
	Type t;
	__asm__ __volatile__("rdrand %0" : "=r"(t));
	return t;
}

bool has_rdrand = false;

unsigned long get_seed()
{
	return get_hwrandom();
}

unsigned long get_hwrandom()
{
	// We're using the current timestamp as entropy, + whatever we got in rdrand
	auto timestamp = rdtsc();

	if(has_rdrand)
	{
		auto extra_entropy = rdrand<uint64_t>();
		return extra_entropy & ~(timestamp & 0xffff);
	}

	// FIXME: This is horrible RNG
	return timestamp ^ (timestamp >> 16);
}

void init_random()
{
	has_rdrand = x86_has_cap(X86_FEATURE_RDRND);
}

}

}
