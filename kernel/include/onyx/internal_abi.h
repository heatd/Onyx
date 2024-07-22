/*
 * Copyright (c) 2021 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 */

#ifndef _ONYX_INTERNAL_ABI_H
#define _ONYX_INTERNAL_ABI_H

#include <platform/internal_abi.h>

#ifndef __ASSEMBLER__
namespace abi
{
internal_abi_layout *get_abi_data();
extern "C" void init_ssp_for_cpu(unsigned int cpu_nr);
} // namespace abi

#endif
#endif
