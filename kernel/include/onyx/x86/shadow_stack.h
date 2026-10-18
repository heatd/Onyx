/*
 * Copyright (c) 2026 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#ifndef _ONYX_X86_SHADOW_STACK_H
#define _ONYX_X86_SHADOW_STACK_H

#include <onyx/compiler.h>
#include <onyx/x86/msr.h>

/* For arch_prctl(2) */
#define ARCH_SHSTK_ENABLE  0x5001
#define ARCH_SHSTK_DISABLE 0x5002
#define ARCH_SHSTK_LOCK    0x5003
#define ARCH_SHSTK_UNLOCK  0x5004
#define ARCH_SHSTK_STATUS  0x5005

/* ARCH_SHSTK_ features bits */
#define ARCH_SHSTK_SHSTK (1ULL << 0)
#define ARCH_SHSTK_WRSS  (1ULL << 1)

__BEGIN_CDECLS
int shstk_clone_thread(struct thread *newthr, struct thread *src);
void shstk_clear(void);
int shstk_prctl(int code, unsigned long arg);
__END_CDECLS
#endif
