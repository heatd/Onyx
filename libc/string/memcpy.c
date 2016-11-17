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
#include <string.h>
#include <stdint.h>
#include <xmmintrin.h>
static inline void *__movsb(void *d, const void *s, size_t n)
{
        asm("rep movsb"
                : "=D" (d),
                  "=S" (s),
                  "=c" (n)
                : "0" (d),
                  "1" (s),
                  "2" (n)
                : "memory");
        return d;
}
void *memcpy(void *__restrict__ dstptr, const void *__restrict__ srcptr,
	     size_t size)
{	
	__movsb(dstptr, srcptr, size);
	return dstptr;
}
