/*
 * Copyright (c) 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#include <stdint.h>

extern uint64_t boot_page_tables[];

__attribute__((section(".boot"))) __attribute__((no_sanitize("undefined"))) void
early_paging_setup()
{
    uint64_t *top_page_table = boot_page_tables;
    uint64_t *second_level[2] = {&boot_page_tables[512], &boot_page_tables[1024]};

    top_page_table[0] = ((uint64_t)second_level[0] >> 12) << 10 | 1;
    top_page_table[511] = ((uint64_t)second_level[1] >> 12) << 10 | 1;

    second_level[0][0] = 0 | 0xf;
    second_level[0][1] = (0x40000000 >> 12) << 10 | 0xf;
    second_level[0][2] = (0x80000000 >> 12) << 10 | 0xf;
    second_level[0][3] = (0xc0000000 >> 12) << 10 | 0xf;

    second_level[1][510] = (0x80000000 >> 12) << 10 | 0xf;
    second_level[1][511] = (0xc0000000 >> 12) << 10 | 0xf;
}
