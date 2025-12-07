#ifndef _LINUX_GFP_H
#define _LINUX_GFP_H

typedef unsigned int gfp_t;
#include <onyx/page.h>

#define __GFP_NOFAIL 0
#define __GFP_NORETRY 0
#define __GFP_ACCOUNT 0

#define __GFP_BITS_MASK ((1UL << __GFP_BITS_SHIFT) - 1)
#define GFP_ZONEMASK (__GFP_DMA32)

#endif
