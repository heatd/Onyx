#ifndef _LINUX_BITS_H
#define _LINUX_BITS_H

#include <asm-generic/bitsperlong.h>
#include <linux/build_bug.h>
#include <linux/overflow.h>

#define BIT_MASK(nr)		(UL(1) << ((nr) % BITS_PER_LONG))
#define BIT_WORD(nr)		((nr) / BITS_PER_LONG)
#define BIT_ULL_MASK(nr)	(ULL(1) << ((nr) % BITS_PER_LONG_LONG))
#define BIT_ULL_WORD(nr)	((nr) / BITS_PER_LONG_LONG)
#define BITS_PER_BYTE		8
#define BITS_PER_TYPE(type)	(sizeof(type) * BITS_PER_BYTE)

#define GENMASK_INPUT_CHECK(h, l) BUILD_BUG_ON_ZERO(const_true((l) > (h)))

/*
 * Generate a mask for the specified type @t. Additional checks are made to
 * guarantee the value returned fits in that type, relying on
 * -Wshift-count-overflow compiler check to detect incompatible arguments.
 * For example, all these create build errors or warnings:
 *
 * - GENMASK(15, 20): wrong argument order
 * - GENMASK(72, 15): doesn't fit unsigned long
 * - GENMASK_U32(33, 15): doesn't fit in a u32
 */
#define GENMASK_TYPE(t, h, l)					\
	((t)(GENMASK_INPUT_CHECK(h, l) +			\
	     (type_max(t) << (l) &				\
	      type_max(t) >> (BITS_PER_TYPE(t) - 1 - (h)))))

#define GENMASK(h, l)		GENMASK_TYPE(unsigned long, h, l)
#define GENMASK_ULL(h, l)	GENMASK_TYPE(unsigned long long, h, l)

#define GENMASK_U8(h, l)	GENMASK_TYPE(u8, h, l)
#define GENMASK_U16(h, l)	GENMASK_TYPE(u16, h, l)
#define GENMASK_U32(h, l)	GENMASK_TYPE(u32, h, l)
#define GENMASK_U64(h, l)	GENMASK_TYPE(u64, h, l)
#define GENMASK_U128(h, l)	GENMASK_TYPE(u128, h, l)

#ifdef __ASSEMBLY__
#define _AC(X,Y)	X
#define _AT(T,X)	X
#else
#define __AC(X,Y)	(X##Y)
#define _AC(X,Y)	__AC(X,Y)
#define _AT(T,X)	((T)(X))
#endif

#define _UL(x)		(_AC(x, UL))
#define _ULL(x)		(_AC(x, ULL))

#define _BITUL(x)	(_UL(1) << (x))
#define _BITULL(x)	(_ULL(1) << (x))

#define BIT(n) _BITUL(n)
#define BIT_ULL(nr)		_BITULL(nr)


#endif
