#ifndef _LINUX_OVERFLOW_H
#define _LINUX_OVERFLOW_H

#include <linux/compiler.h>
#include <linux/stddef.h>

#define __type_half_max(type) ((type)1 << (8*sizeof(type) - 1 - is_signed_type(type)))
#define __type_max(T) ((T)((__type_half_max(T) - 1) + __type_half_max(T)))
#define type_max(t)	__type_max(typeof(t))

static inline size_t size_safe_mul(size_t a, size_t b)
{
    size_t result;

    if (check_mul_overflow(a, b, &result))
        return SIZE_MAX;
    return result;
}

#define array_size(a, b)	size_safe_mul(a, b)

#endif
