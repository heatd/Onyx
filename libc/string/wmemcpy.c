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

wchar_t *wmemcpy(wchar_t *restrict ws1, const wchar_t *restrict ws2, size_t n)
{
	for(size_t i = 0; i < n; i++)
	{
		ws1[i] = ws2[i];
	}
	return ws1;
}