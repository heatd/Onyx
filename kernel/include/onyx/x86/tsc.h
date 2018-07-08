/*
* Copyright (c) 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#ifndef _ONYX_X86_TSC_H
#define _ONYX_X86_TSC_H

#include <onyx/vdso.h>

void tsc_setup_vdso(struct vdso_time *time);
void tsc_init(void);

#endif