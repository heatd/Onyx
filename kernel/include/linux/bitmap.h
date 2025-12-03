#ifndef _LINUX_BITMAP_H
#define _LINUX_BITMAP_H

#include <linux/types.h>
#include <linux/bits.h>

#define BITMAP_FIRST_WORD_MASK(start) (~0UL << ((start) & (BITS_PER_LONG - 1)))
#define BITMAP_LAST_WORD_MASK(nbits) (~0UL >> (-(nbits) & (BITS_PER_LONG - 1)))

static inline unsigned long find_next_bit(const unsigned long *bitmap, unsigned long bits,
    unsigned long start)
{
    unsigned long i, tmp;

    if (start > bits)
        goto out;

    for (i = (start / BITS_PER_LONG); i < BITS_TO_LONGS(bits); i++)
    {
        tmp = bitmap[i];
        if (i == (start / BITS_PER_LONG))
            tmp &= BITMAP_FIRST_WORD_MASK(start);
        if (tmp == 0)
            continue;
        tmp = i * BITS_PER_LONG + (__builtin_ffsl(tmp) - 1);
        if (tmp >= bits)
            goto out;
        return tmp;
    }

out:
    return bits;
}

static inline unsigned long find_first_zero_bit(const unsigned long *bitmap, unsigned long bits)
{
    unsigned long i, tmp;

    for (i = 0; i < BITS_TO_LONGS(bits); i++)
    {
        tmp = bitmap[i];
        /* TODO: properly handle start... */
        if (tmp == -1UL)
            continue;
        tmp = i * BITS_PER_LONG + (__builtin_ffsl(~tmp) - 1);
        if (tmp >= bits)
            goto out;
        return tmp;
    }

out:
    return bits;
}

static inline unsigned int bitmap_weight(const unsigned long *bitmap, unsigned int bits)
{
    unsigned long i, res = 0;

    for (i = 0; i < BITS_TO_LONGS(bits) - 1; i++)
        res += __builtin_popcountl(bitmap[i]);
    return res + __builtin_popcountl(bitmap[BITS_TO_LONGS(bits) - 1] & BITMAP_LAST_WORD_MASK(bits));
}

#define for_each_set_bit(bit, addr, size) \
	for ((bit) = 0; (bit) = find_next_bit((addr), (size), (bit)), (bit) < (size); (bit)++)

static inline bool bitmap_andnot(unsigned long *dst, const unsigned long *bitmap1,
				const unsigned long *bitmap2, unsigned int bits)
{
	unsigned int k;
	unsigned int lim = bits/BITS_PER_LONG;
	unsigned long result = 0;

	for (k = 0; k < lim; k++)
		result |= (dst[k] = bitmap1[k] & ~bitmap2[k]);
	if (bits % BITS_PER_LONG)
		result |= (dst[k] = bitmap1[k] & ~bitmap2[k] &
			   BITMAP_LAST_WORD_MASK(bits));
	return result != 0;
}

static inline void bitmap_clear(unsigned long *map, unsigned int start, int len)
{
	unsigned long *p = map + BIT_WORD(start);
	const unsigned int size = start + len;
	int bits_to_clear = BITS_PER_LONG - (start % BITS_PER_LONG);
	unsigned long mask_to_clear = BITMAP_FIRST_WORD_MASK(start);

	while (len - bits_to_clear >= 0) {
		*p &= ~mask_to_clear;
		len -= bits_to_clear;
		bits_to_clear = BITS_PER_LONG;
		mask_to_clear = ~0UL;
		p++;
	}
	if (len) {
		mask_to_clear &= BITMAP_LAST_WORD_MASK(size);
		*p &= ~mask_to_clear;
	}
}


#endif
