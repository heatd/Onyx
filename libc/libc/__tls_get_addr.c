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
void *__tls_get_addr(size_t *v)
{
	(void) v;
	void *ret = NULL;
	asm volatile("movq %%gs:0x0, %0"::"r"(ret));
	return ret;
}