/*
 * Copyright (c) 2024 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef _UAPI_MINCORE_H
#define _UAPI_MINCORE_H

#define PAGE_PRESENT    (1 << 0)
#define PAGE_GLOBAL     (1 << 1)
#define PAGE_WRITABLE   (1 << 2)
#define PAGE_EXECUTABLE (1 << 3)
#define PAGE_DIRTY      (1 << 4)
#define PAGE_ACCESSED   (1 << 5)
#define PAGE_USER       (1 << 6)
#define PAGE_HUGE       (1 << 7)

/* Reserve the 12 bottom bits for flags, this lines up nicely with 4K pages */

#define MAPPING_INFO_PADDR(x) ((x) & -4096UL)

#endif
