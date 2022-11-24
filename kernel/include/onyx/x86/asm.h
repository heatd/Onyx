/*
 * Copyright (c) 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef _ONYX_X86_ASM_H
#define _ONYX_X86_ASM_H

// clang-format off

#ifdef __ASSEMBLY__

.macro RET
#ifdef CONFIG_X86_RETHUNK
    jmp __x86_return_thunk
#else
    ret
#ifdef CONFIG_X86_MITIGATE_SLS
    int3
#endif
#endif
.endm

#endif
#endif
