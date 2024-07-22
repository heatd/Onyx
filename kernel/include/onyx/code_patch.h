/*
 * Copyright (c) 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#ifndef _ONYX_CODE_PATCH_H
#define _ONYX_CODE_PATCH_H

#include <stddef.h>
#include <stdint.h>

namespace code_patch
{

/**
 * @brief Replaces instructions at ip with nops, optimised for performance
 *
 * @param ip Instruction pointer
 * @param size Size of region
 */
void nop_out(void *ip, size_t size);

/**
 * @brief Replaces instructions at ip with instructions at *instructions, of size size, and nops the
 * rest
 *
 * @param ip
 * @param instructions
 * @param size
 * @param max
 */
void replace_instructions(void *ip, const void *instructions, size_t size, size_t max);

} // namespace code_patch

#endif
