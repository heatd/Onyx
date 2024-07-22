/*
 * Copyright (c) 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include "memset_impl.S"

ALIGN_TEXT
.global __memset
.type __memset, @function
__memset:
    /* Set up the return value */
    mov %rdi, %rax
    memset_like _memset
.size __memset, . - __memset 

.weak memset
.set memset, __memset
