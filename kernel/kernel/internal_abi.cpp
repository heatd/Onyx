/*
* Copyright (c) 2021 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#include <onyx/percpu.h>
#include <onyx/internal_abi.h>

namespace abi
{

PER_CPU_VAR_ABI(internal_abi_layout abi_data);

internal_abi_layout *get_abi_data()
{
	return get_per_cpu_ptr(abi_data);
}

}