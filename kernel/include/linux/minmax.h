/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_MINMAX_H
#define _LINUX_MINMAX_H

#include <onyx/utils.h>
/**
 * swap - swap values of @a and @b
 * @a: first value
 * @b: second value
 */
#define swap(a, b) \
	do { typeof(a) __tmp = (a); (a) = (b); (b) = __tmp; } while (0)

#define __clamp(val, lo, hi)	\
	((val) >= (hi) ? (hi) : ((val) <= (lo) ? (lo) : (val)))

#define __clamp_type(type, val, lo, hi) ({  \
	type v = (val);							\
	type l = (lo);							\
	type h = (hi);							\
	__clamp(v, l, h);						\
})

#define __cmp_op_min <
#define __cmp_op_max >

#define __cmp(op, x, y)	((x) __cmp_op_##op (y) ? (x) : (y))

#define __cmp_once_unique(op, type, x, y, ux, uy) \
	({ type ux = (x); type uy = (y); __cmp(op, ux, uy); })

#define __cmp_once(op, type, x, y) \
	__cmp_once_unique(op, type, x, y, __UNIQUE_ID(x_), __UNIQUE_ID(y_))

/**
 * min_t - return minimum of two values, using the specified type
 * @type: data type to use
 * @x: first value
 * @y: second value
 */
#define min_t(type, x, y) __cmp_once(min, type, x, y)

#define clamp_val(val, lo, hi) __clamp_type(typeof(val), val, lo, hi)

#define clamp(val, lo, hi)  __clamp_type(__auto_type, val, lo, hi)
/*
 * Use these carefully: no type checking, and uses the arguments
 * multiple times. Use for obvious constants only.
 */
#define MIN(a, b) __cmp(min, a, b)
#define MAX(a, b) __cmp(max, a, b)
#define MIN_T(type, a, b) __cmp(min, (type)(a), (type)(b))
#define MAX_T(type, a, b) __cmp(max, (type)(a), (type)(b))

#endif	/* _LINUX_MINMAX_H */
