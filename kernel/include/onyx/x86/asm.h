/*
 * Copyright (c) 2022 - 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#ifndef _ONYX_X86_ASM_H
#define _ONYX_X86_ASM_H

// clang-format off

#ifdef __ASSEMBLER__

#ifdef CONFIG_X86_RETHUNK
#define RET jmp __x86_return_thunk
#elif defined(CONFIG_X86_GPLv2IGATE_SLS)
#define RET ret; int3
#else
#define RET ret
#endif

#define ENTRY_LOCAL(name) .type name, @function; name:
#define ENTRY(name) .global name; ENTRY_LOCAL(name)

#define END(name) .size name, . - name

#endif
#endif
