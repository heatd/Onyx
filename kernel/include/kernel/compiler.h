/*----------------------------------------------------------------------
 * Copyright (C) 2016 Pedro Falcato
 *
 * This file is part of Spartix, and is made available under
 * the terms of the GNU General Public License version 2.
 *
 * You can redistribute it and/or modify it under the terms of the GNU
 * General Public License version 2 as published by the Free Software
 * Foundation.
 *----------------------------------------------------------------------*/
/**************************************************************************
 *
 *
 * File: compiler.h
 *
 * Description: Contains GCC specific features and builtins
 *
 * Date: 1/2/2016
 *
 *
 **************************************************************************/
#ifndef COMPILER_H
#define COMPILER_H

#include <stdint.h>
#ifndef __GNUC__
#error "The OS needs to be compiled using GCC"
#endif /*__GNUC__ */
#ifndef __spartix__
#error "Spartix needs to be compiled using a Spartix Cross Compiler"
#endif /* __spartix__ */
#define likely(x)      __builtin_expect(!!(x), 1)
#define unlikely(x)    __builtin_expect(!!(x), 0)
#define prefetch(x,y,z) __builtin_prefetch(x,y,z)
#define ASSUME_ALIGNED(x,y) __builtin_assume_aligned(x,y)
#define ARCH_SPECIFIC extern
inline uint64_t rdtsc()
{
    	uint64_t ret;
    	__asm__ __volatile__ ( "rdtsc" : "=A"(ret) );
    	return ret;
}
#endif /* COMPILER_H */
