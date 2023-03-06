/*
 * Copyright (c) 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
#include "memcpy_impl.S"

ALIGN_TEXT
.global __memcpy
.type __memcpy, @function
__memcpy:
    /* Set up the return value */
    mov %rdi, %rax
    memcpy_like 0 _memcpy

.size __memcpy, . - __memcpy 

ALIGN_TEXT
.global __memmove
.type __memmove, @function
__memmove:
    /* Set up the return value */
    mov %rdi, %rax
    memcpy_like 1 _memset

.size __memmove, . - __memmove 

.weak memcpy
.set memcpy, __memcpy
.weak memmove
.set memmove, __memmove
