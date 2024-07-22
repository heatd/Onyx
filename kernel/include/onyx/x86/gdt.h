/*
 * Copyright (c) 2017 - 2021 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#ifndef _ONYX_X86_GDT_H
#define _ONYX_X86_GDT_H

#include <stdint.h>

typedef struct
{
    uint16_t size;
    uint64_t ptr;
} __attribute__((packed)) gdtr_t;

union tss_descriptor {
    struct
    {
        uint16_t limit_low;
        uint16_t base_low;
        uint8_t base_16_23;
        uint8_t type;
        uint8_t limit_flags;
        uint8_t base_mid;
        uint32_t base_high;
        uint32_t reserved;
    };

    uint64_t __raw[2];
} __attribute__((packed));

#define TSS_TYPE_INACTIVE (0b1001)
#define TSS_TYPE_BUSY     (0b1011)

#define TSS_TYPE_DPL(dpl) (dpl << 5)
#define TSS_TYPE_PRESENT  (1 << 7)

void gdt_init_percpu(void);

#endif
