#ifndef _LINUX_BITOPS_H
#define _LINUX_BITOPS_H

#include <stdbool.h>
#include <onyx/atomic.h>
#include <onyx/types.h>
#include <linux/bits.h>

#include <asm-generic/bitsperlong.h>

static inline bool test_bit(unsigned long nr, const unsigned long *word)
{
    return READ_ONCE(word[BIT_WORD(nr)]) & BIT_MASK(nr);
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
    word[BIT_WORD(nr)] |= BIT_MASK(nr);
}

static inline void __clear_bit(unsigned long nr, unsigned long *word)
{
    word[BIT_WORD(nr)] &= ~BIT_MASK(nr);
}

#define __ffs(n) (__builtin_ffsl(n) - 1)

#define hweight32(bits) (__builtin_popcount(bits))
#define hweight64(bits) (__builtin_popcountl(bits))

static inline void clear_bit_unlock(unsigned long nr, unsigned long *word)
{
    __atomic_and_fetch(word + BIT_WORD(nr), ~BIT_MASK(nr), __ATOMIC_RELEASE);
}

static inline bool __test_and_set_bit(unsigned long nr, unsigned long *word)
{
    unsigned long old = word[BIT_WORD(nr)];
    word[BIT_WORD(nr)] |= BIT_MASK(nr);
    return old & BIT_MASK(nr);
}

static inline bool __test_and_clear_bit(unsigned long nr, unsigned long *word)
{
    unsigned long old = word[BIT_WORD(nr)];
    word[BIT_WORD(nr)] &= ~BIT_MASK(nr);
    return old & BIT_MASK(nr);
}

#endif
