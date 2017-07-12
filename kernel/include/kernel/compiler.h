/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
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
#ifndef __onyx__
#error "Onyx needs to be compiled using a Onyx Cross Compiler"
#endif /* __onyx__ */
#define align(x) __attribute__((aligned(x)))
#define __align_cache align(16)
#define likely(x)      __builtin_expect(!!(x), 1)
#define unlikely(x)    __builtin_expect(!!(x), 0)
#define prefetch(...) __builtin_prefetch(__VA_ARGS__)
#define ASSUME_ALIGNED(x,y) __builtin_assume_aligned(x,y)
#define ARCH_SPECIFIC extern
#define UNUSED_PARAMETER(x) (void)x
#define UNUSED(x) UNUSED_PARAMETER(x)
#define __init __attribute__((constructor))
inline uint64_t rdtsc()
{
    	uint64_t ret = 0;
    	__asm__ __volatile__ ( "rdtsc" : "=A"(ret) );
    	return ret;
}
inline int count_bits32(uint32_t num)
{
	int nbits = 0;
	for(int i = 0; i < 32; i++)
	{
		if(num & 1)
			nbits++;
		num = num >> 1;
	}
	return nbits;
}
inline int count_bits64(uint64_t num)
{
	int nbits = 0;
	for(int i = 0; i < 64; i++)
	{
		if(num & 1)
			nbits++;
		num = num >> 1;
	}
	return nbits;
}
#define add_check_overflow(op1, op2, res) __builtin_add_overflow(op1, op2, res)
#endif /* COMPILER_H */
