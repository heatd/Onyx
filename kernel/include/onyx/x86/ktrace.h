/*
* Copyright (c) 2020, 2021 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _ONYX_X86_KTRACE_H
#define _ONYX_X86_KTRACE_H

#include <stddef.h>
#include <onyx/registers.h>

#ifdef __cplusplus
extern "C" {
#endif

void ktrace_int3_handler(struct registers *regs);

#ifdef __cplusplus
}

namespace ktrace
{

/**
 * @brief Replaces instructions at ip with nops, optimised for performance
 * 
 * @param ip Instruction pointer
 * @param size Size of region
 */
void nop_out(void *ip, size_t size);

/**
 * @brief Replaces instructions at ip with instructions at *instructions, of size size, and nops the rest
 * 
 * @param ip 
 * @param instructions 
 * @param size
 * @param max
 */
void replace_instructions(void *ip, const void *instructions, size_t size, size_t max);

}

#endif

#endif
