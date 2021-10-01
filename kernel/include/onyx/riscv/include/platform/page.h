/*
* Copyright (c) 2021 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#ifndef _ONYX_RISCV_PAGE_H
#define _ONYX_RISCV_PAGE_H

#define PAGE_SHIFT	12

// Note that page size may already be defined by some other weird header, like onyx/limits.h!
#undef PAGE_SIZE
#define PAGE_SIZE 4096UL

#define HUGEPAGE_SHIFT	21

#define DMA_MAX_ADDR	(0x1000000)


#endif
