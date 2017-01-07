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
#ifndef _FPU_H
#define _FPU_H

#ifdef __x86_64__

#define FPU_AREA_ALIGNMENT 	16
#define FPU_AREA_SIZE		512
#define SAVE_FPU(addr) asm volatile("fxsave %0"::"m"(addr));
#define RESTORE_FPU(addr) asm volatile("fxrstor %0"::"m"(addr));

#else
#error "Implement FPU switching for your arch"
#endif

#endif