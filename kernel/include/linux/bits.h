#ifndef _LINUX_BITS_H
#define _LINUX_BITS_H

#include <asm-generic/bitsperlong.h>

#define BIT_MASK(nr)		(UL(1) << ((nr) % BITS_PER_LONG))
#define BIT_WORD(nr)		((nr) / BITS_PER_LONG)
#define BIT_ULL_MASK(nr)	(ULL(1) << ((nr) % BITS_PER_LONG_LONG))
#define BIT_ULL_WORD(nr)	((nr) / BITS_PER_LONG_LONG)
#define BITS_PER_BYTE		8
#define BITS_PER_TYPE(type)	(sizeof(type) * BITS_PER_BYTE)

#endif
