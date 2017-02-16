/*----------------------------------------------------------------------
 * Copyright (C) 2016, 2017 Pedro Falcato
 *
 * This file is part of Onyx, and is made available under
 * the terms of the GNU General Public License version 2.
 *
 * You can redistribute it and/or modify it under the terms of the GNU
 * General Public License version 2 as published by the Free Software
 * Foundation.
 *----------------------------------------------------------------------*/

#ifndef _SETJMP_H
#define _SETJMP_H
#include <sys/cdefs.h>
typedef unsigned long sigjmp_buf[8];

typedef sigjmp_buf jmp_buf;

#ifdef __cplusplus
__START_C_HEADER
#endif

int setjmp(jmp_buf env);
int sigsetjmp(sigjmp_buf env, int savesigs);
void longjmp(jmp_buf env, int val);
void siglongjmp(sigjmp_buf env, int val);

#ifdef __cplusplus
__END_C_HEADER
#endif
#endif
