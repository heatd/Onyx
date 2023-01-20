/*
 * Copyright (c) 2018 - 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
.section .data, "aw"

.global __vdso_start
.global __vdso_end

.balign 0x1000
__vdso_start:	.incbin "onyx-vdso.so.0"
.balign 0x1000
__vdso_end:
