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
#define weak_alias(name, aliasname) _weak_alias (name, aliasname)
#define _weak_alias(name, aliasname) \
extern __typeof (name) aliasname __attribute__ ((weak, alias (#name)));

#define strong_alias(name, aliasname) _strong_alias (name, aliasname)
#define _strong_alias(name, aliasname) \
extern __typeof (name) aliasname __attribute__ ((alias (#name)));

#define USES_FANCY_START	_Pragma("GCC push_options") \
_Pragma("GCC target(\"sse2\", \"3dnow\", \"xsave\")")
#define USES_FANCY_END _Pragma("GCC pop_options")

static inline uint64_t rdtsc(void)
{
    	union
	{
		uint64_t value;
		uint32_t lohi[2];
	} v;
	
	__asm__ __volatile__ ("rdtscp" : "=a"(v.lohi[0]), "=d"(v.lohi[1]) :: "ecx");
    return v.value;
}

static inline int count_bits32(uint32_t num)
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

static inline int count_bits64(uint64_t num)
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

#define ___PASTE(a,b) a##b
#define __PASTE(a,b) ___PASTE(a,b)

#define COMPILER_BARRIER()		__asm__ __volatile__("" ::: "memory")
#define ilog2(X) ((unsigned) (8*sizeof (unsigned long long) - __builtin_clzll((X)) - 1))
#define ALIGN_TO(x, y) (((unsigned long)x + (y - 1)) & -y)

#define OPTIMISE_DEBUG __attribute__((optimize("Og")))

#ifdef __x86_64__

#define write_memory_barrier()	__asm__ __volatile__("sfence" ::: "memory")
#define read_memory_barrier()	__asm__ __volatile__("lfence" ::: "memory")

#endif

#endif /* COMPILER_H */
