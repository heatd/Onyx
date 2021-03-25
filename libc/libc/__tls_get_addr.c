/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
/**************************************************************************
 *
 *
 * File: __tls_get_addr.c
 *
 * Description: Implementation of __tls_get_addr(). Not correct, just a stub for errno!
 *
 * Date: 6/11/2016
 *
 *
 **************************************************************************/
#include <stddef.h>

#ifdef __x86_64__

void *__tls_get_addr(size_t *v)
{
	(void) v;
	void *ret = NULL;
	__asm__ __volatile__("movq %%fs:0x0, %0"::"r"(ret));
	return ret;
}

#endif
