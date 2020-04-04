/*
* Copyright (c) 2019 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#ifndef _ONYX_FRACT_H
#define _ONYX_FRACT_H

#include <stdint.h>
#include <stdio.h>

struct fraction
{
	unsigned long numerator;
	unsigned long denominator;
};

static inline unsigned long gcd(unsigned long n, unsigned long m)
{
	while(m > 0)
	{
		unsigned long temp = n % m;
		n = m;
		m = temp;
	}

	return n;
}

static inline struct fraction fract_mult(struct fraction *f1, struct fraction *f2)
{
	struct fraction r = {f1->numerator * f2->numerator, f1->denominator * f2->denominator};
	return r;
}

static inline struct fraction fract_div(struct fraction *f1, struct fraction *f2)
{
	struct fraction r = {f1->numerator * f2->denominator, f1->denominator * f2->numerator};
	return r;
}

#define INT_DIV_ROUND_CLOSEST(x, y)		(((x) + ((y)/2)) / (y))

static inline uint64_t fract_div_u64_fract(uint64_t u, struct fraction *f)
{
	struct fraction f2;
	if(__builtin_umull_overflow(u,  f->denominator, &f2.numerator))
	{
		printk("Overflow! with u %lu and denominator %lu\n", u, f->denominator);
	}

	f2.denominator = f->numerator;

	return INT_DIV_ROUND_CLOSEST(f2.numerator, f2.denominator);
}

static inline uint64_t fract_mult_u64_fract(uint64_t u, struct fraction *f)
{
	struct fraction f2;
	
	if(__builtin_umull_overflow(u,  f->numerator, &f2.numerator))
	{
		printk("Overflow! with u %lu and numerator %lu\n", u, f->numerator);
	}

	f2.denominator = f->denominator;

	return INT_DIV_ROUND_CLOSEST(f2.numerator, f2.denominator);
}

static inline void fract_reduce(struct fraction *f)
{
	unsigned long common_div = gcd(f->numerator, f->denominator);
	f->numerator /= common_div;
	f->denominator /= common_div;
}

static inline unsigned long fract_get_int(struct fraction *f)
{
	return INT_DIV_ROUND_CLOSEST(f->numerator, f->denominator);
}

#endif