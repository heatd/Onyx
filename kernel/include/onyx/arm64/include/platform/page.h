/*
 * Copyright (c) 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef _ONYX_ARM64_PAGE_H
#define _ONYX_ARM64_PAGE_H

#define PAGE_SHIFT 12

// Note that page size may already be defined by some other weird header, like onyx/limits.h!
#undef PAGE_SIZE
#define PAGE_SIZE 4096UL

#define HUGEPAGE_SHIFT 21

#define DMA_MAX_ADDR (0x1000000)

#endif
