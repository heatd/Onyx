/*
* Copyright (c) 2021 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#ifndef _ONYX_INTERNAL_ABI_H
#define _ONYX_INTERNAL_ABI_H

#include <platform/internal_abi.h>

namespace abi
{
	internal_abi_layout *get_abi_data();
	extern "C"
	void init_ssp_for_cpu(unsigned int cpu_nr);
}

#endif
