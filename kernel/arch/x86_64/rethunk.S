/*
 * Copyright (c) 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <onyx/x86/asm.h>

/* TODO: Look at (https://www.amd.com/system/files/documents/technical-
guidance-for-mitigating-branch-type-confusion.pdf) section 6.1 */
.align 64
ENTRY(__x86_return_thunk)
    ret
    int3
END(__x86_return_thunk)
