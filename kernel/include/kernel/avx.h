/*----------------------------------------------------------------------
 * Copyright (C) 2017 Pedro Falcato
 *
 * This file is part of Spartix, and is made available under
 * the terms of the GNU General Public License version 2.
 *
 * You can redistribute it and/or modify it under the terms of the GNU
 * General Public License version 2 as published by the Free Software
 * Foundation.
 *----------------------------------------------------------------------*/
#ifndef _KERNEL_AVX_H
#define _KERNEL_AVX_H

#define AVX_XCR0_FPU	(1 << 0)
#define AVX_XCR0_SSE	(1 << 1)
#define AVX_XCR0_AVX	(1 << 2)
void avx_init(void);


#endif