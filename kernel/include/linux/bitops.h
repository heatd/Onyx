#ifndef _LINUX_BITOPS_H
#define _LINUX_BITOPS_H

#include <stdbool.h>
#include <onyx/atomic.h>
#include <onyx/types.h>

static inline bool test_bit(unsigned long nr, const unsigned long *word)
{
    return READ_ONCE(*word) & (1UL << nr);
}

/**
 * rol32 - rotate a 32-bit value left
 * @word: value to rotate
 * @shift: bits to roll
 */
static inline __u32 rol32(__u32 word, unsigned int shift)
{
	return (word << (shift & 31)) | (word >> ((-shift) & 31));
}

/* __ variants are not atomic */
static inline void __set_bit(unsigned long nr, unsigned long *word)
{
    *word |= (1UL << nr);
}

static inline void __clear_bit(unsigned long nr, unsigned long *word)
{
    *word &= ~(1UL << nr);
}

#define __ffs(n) (__builtin_ffsl(n) - 1)

#define hweight32(bits) (__builtin_popcount(bits))
#define hweight64(bits) (__builtin_popcountl(bits))

static inline void clear_bit_unlock(unsigned long nr, unsigned long *word)
{
    __atomic_and_fetch(word, ~(1UL << nr), __ATOMIC_RELEASE);
}

static inline bool __test_and_set_bit(unsigned long nr, unsigned long *word)
{
    unsigned long old = *word;
    *word |= (1UL << nr);
    return old & (1UL << nr);
}

static inline bool __test_and_clear_bit(unsigned long nr, unsigned long *word)
{
    unsigned long old = *word;
    *word &= ~(1UL << nr);
    return old & (1UL << nr);
}

#endif
