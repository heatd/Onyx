/*
* Copyright (c) 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _KERNEL_AVX_H
#define _KERNEL_AVX_H

#define AVX_XCR0_FPU	(1 << 0)
#define AVX_XCR0_SSE	(1 << 1)
#define AVX_XCR0_AVX	(1 << 2)

void avx_init(void);


#endif