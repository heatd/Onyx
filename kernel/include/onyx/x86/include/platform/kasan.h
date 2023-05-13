/*
 * Copyright (c) 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef _ONYX_X86_PLATFORM_KASAN_H
#define _ONYX_X86_PLATFORM_KASAN_H

extern unsigned long __x86_kasan_virt;
extern unsigned long __x86_kasan_end;

#define KASAN_VIRT_START __x86_kasan_virt
#define KASAN_VIRT_END   // unused

#define KASAN_SHADOW_OFFSET 0xdffffc0000000000

#endif
