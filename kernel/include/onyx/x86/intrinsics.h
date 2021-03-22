/*
* Copyright (c) 2021 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#ifndef _ONYX_X86_INTRINSICS_H
#define _ONYX_X86_INTRINSICS_H

template <typename Type>
static inline void mov_non_temporal(volatile Type *p, Type val)
{
	__asm__ __volatile__("movnti %1, %0" : "=m" (*p) : "r" (val) : "memory");
}


#endif
