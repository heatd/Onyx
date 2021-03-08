/*
* Copyright (c) 2018 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#ifndef _ONYX_COPY_H
#define _ONYX_COPY_H

#include <stddef.h>
#include <stdint.h>

#include <assert.h>

#include <onyx/compiler.h>

#define NATIVE_BUFFER_ALIGNMENT		(sizeof(uintptr_t))

#define IS_NATIVE_ALIGNED(d)	!(d & (NATIVE_BUFFER_ALIGNMENT - 1))

void __copy_non_temporal(void *d, void *s, size_t count);

static inline void copy_non_temporal(void *d, void *s, size_t count)
{
	assert(likely(IS_NATIVE_ALIGNED((uintptr_t) d)));
	assert(likely(IS_NATIVE_ALIGNED((uintptr_t) s)));
	assert(likely(IS_NATIVE_ALIGNED((uintptr_t) count)));

	__copy_non_temporal(d, s, count);
}

void __set_non_temporal(void *d, int b, size_t count);

static inline void set_non_temporal(void *d, int b, size_t count)
{
	assert(likely(IS_NATIVE_ALIGNED((uintptr_t) d)));
	assert(likely(IS_NATIVE_ALIGNED((uintptr_t) count)));

	__set_non_temporal(d, b, count);
}

#endif
