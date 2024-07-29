/*
 * Copyright (c) 2024 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#ifndef _ONYX_X86_PLATFORM_BUG_H
#define _ONYX_X86_PLATFORM_BUG_H

struct bug
{
    unsigned long addr;
    const char *file;
    unsigned int line;
    unsigned int flags;
};

#define BUG_FLAG_WARN (1 << 0)

/* Capture more bug info by using ud2 to induce an invalid opcode trap. We'll handle the WARN or BUG
 * in the trap handler, and (in warnings) resume by skipping over the ud2 */

#define ___BUG(flags)                                                    \
    __asm__ __volatile__("%=: ud2\n"                                     \
                         ".pushsection __bug_tab,\"aM\",@progbits,%c3\n" \
                         ".quad %=b\n"                                   \
                         ".quad %c0\n"                                   \
                         ".long %c1\n"                                   \
                         ".long %c2\n"                                   \
                         ".popsection\n" ::"i"(__FILE__),                \
                         "i"(__LINE__), "i"(flags), "i"(sizeof(struct bug)))

#define __WARN() ___BUG(BUG_FLAG_WARN)

#endif
