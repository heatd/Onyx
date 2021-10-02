/*
 * Copyright (c) 2017 - 2021 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef _ONYX_X86_AVX_H
#define _ONYX_X86_AVX_H

#define AVX_XCR0_FPU	(1 << 0)
#define AVX_XCR0_SSE	(1 << 1)
#define AVX_XCR0_AVX	(1 << 2)


#define AVX_SAVE_ALIGNMENT     64

void avx_init(void);


#endif
