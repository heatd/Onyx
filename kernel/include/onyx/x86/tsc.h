/*
* Copyright (c) 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#ifndef _ONYX_X86_TSC_H
#define _ONYX_X86_TSC_H

#include <onyx/vdso.h>

#ifdef __cplusplus
extern "C" {
#endif

void tsc_setup_vdso(struct vdso_time *time);
void tsc_init(void);
hrtime_t tsc_get_counter_from_ns(hrtime_t t);

#ifdef __cplusplus
}
#endif
#endif
