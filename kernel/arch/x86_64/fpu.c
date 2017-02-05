/*----------------------------------------------------------------------
 * Copyright (C) 2016, 2017 Pedro Falcato
 *
 * This file is part of Spartix, and is made available under
 * the terms of the GNU General Public License version 2.
 *
 * You can redistribute it and/or modify it under the terms of the GNU
 * General Public License version 2 as published by the Free Software
 * Foundation.
 *----------------------------------------------------------------------*/
#include <immintrin.h>
#include <x86intrin.h>
#include <stdio.h>

#include <kernel/fpu.h>
#include <kernel/avx.h>
_Bool avx_supported = false;
void save_fpu(void *address)
{
	if(avx_supported == true)
	{
		_xsave(address, AVX_XCR0_FPU | AVX_XCR0_SSE | AVX_XCR0_AVX);
	}
	else
	{
		_fxsave(address);
	}
}
void restore_fpu(void *address)
{
	if(avx_supported == true)
	{
		_xrstor(address, AVX_XCR0_FPU | AVX_XCR0_SSE | AVX_XCR0_AVX);
	}
	else
	{
		_fxrstor(address);
	}
}