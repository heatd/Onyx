/*
* Copyright (c) 2020 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#ifndef _ONYX_NET_INET_CSUM_H
#define _ONYX_NET_INET_CSUM_H

#include <stdint.h>
#include <stddef.h>

typedef uint32_t __attribute__((may_alias)) may_alias_uint32_t;
typedef uint64_t __attribute__((may_alias)) may_alias_uint64_t;
typedef uint16_t __attribute__((may_alias)) may_alias_uint16_t;
typedef uint8_t __attribute__((may_alias)) may_alias_uint8_t;

#define IS_BUFFER_ALIGNED_TO(buf, boundary)  (((unsigned long) buf) & boundary)

#ifdef __x86_64__

#define ADD_CARRY_64_BYTES(buf, result)  \
__asm__ __volatile__("addq 0*8(%[buf]), %[res]\n\t" \
					 "adcq 1*8(%[buf]), %[res]\n\t" \
					 "adcq 2*8(%[buf]), %[res]\n\t" \
					 "adcq 3*8(%[buf]), %[res]\n\t" \
					 "adcq 4*8(%[buf]), %[res]\n\t" \
					 "adcq 5*8(%[buf]), %[res]\n\t" \
					 "adcq 6*8(%[buf]), %[res]\n\t" \
					 "adcq 7*8(%[buf]), %[res]\n\t" \
					 "adc $0, %[res]" : [res] "=r"(result) \
					 : [buf] "r"(buf), "[res]" "r"(result))

#define ADD_CARRY_64BIT(buf, result) \
__asm__ __volatile__("addq (%1), %0\n\t" \
					 "adc $0, %0\n\t" : "=r"(result) : "r"(buf), "0" "r"(result))

static inline uint16_t fold32_to_16(uint32_t a) 
{
	uint16_t b = a >> 16; 
	__asm__ __volatile__("addw %w2, %w0\n\t"
                         "adcw $0, %w0\n" 
	                     : "=r"(b)
						 : "0"(b), "r"(a));
	return b;
}

static inline uint32_t addcarry32(uint32_t a, uint32_t b)
{
	__asm__ __volatile__("addl %2, %0\n\t"
                         "adcl $0, %0"
                         : "=r"(a)
                         : "0"(a), "rm"(b));
	return a;
}

#endif

using inetsum_t = uint32_t;

inetsum_t do_checksum(const uint8_t *buf, size_t len);

static inline inetsum_t __ipsum_unfolded(const void *addr, size_t bytes, inetsum_t starting_csum)
{
	return addcarry32(starting_csum, do_checksum((const uint8_t *) addr, bytes));
}

static inline inetsum_t ipsum_unfolded(const void *addr, size_t length)
{
	return do_checksum((const uint8_t *) addr, length);
}

static inline uint16_t ipsum_fold(inetsum_t cs)
{
	return ~fold32_to_16(cs);
}

static inline uint16_t ipsum(const void *addr, size_t bytes)
{
	return ipsum_fold(ipsum_unfolded(addr, bytes));
}

#endif
