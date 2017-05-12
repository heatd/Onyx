/*
* Copyright (c) 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _KERNEL_VDSO_H
#define _KERNEL_VDSO_H

void init_vdso(void);
void *map_vdso(void);
#endif