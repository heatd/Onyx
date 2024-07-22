/*
 * Copyright (c) 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <stdint.h>

#include <onyx/arm64/mmu.h>

// We can't #include <onyx/intrinsics.h> because it may have C++
#define msr(reg, value) ({ __asm__ __volatile__("msr " reg ", %0" ::"r"((unsigned long) value)); })
#define isb()           __asm__ __volatile__("isb" ::: "memory")

#define mrs(reg)                                         \
    ({                                                   \
        unsigned long val;                               \
        __asm__ __volatile__("mrs %0," reg : "=r"(val)); \
        val;                                             \
    })

extern uint64_t kernel_phys_offset;

__attribute__((section(".boot"))) __attribute__((no_sanitize("undefined"))) void arm64_setup_mmu(
    uint64_t *boot_page_tables, uint64_t phys_base)
{
    phys_base &= ~(0x200000 - 1);
    kernel_phys_offset = phys_base;
    uint64_t *top_page_table = &boot_page_tables[512];
    uint64_t *bottom_page_table = boot_page_tables;
    uint64_t *second_level[2] = {&boot_page_tables[512UL * 2], &boot_page_tables[512UL * 3]};
    uint64_t *third_level = &boot_page_tables[512UL * 4];

    const uint64_t pt_prot = ARM64_MMU_INNER_SHAREABLE | ARM64_MMU_TABLE | ARM64_MMU_VALID |
                             ARM64_MMU_AF | MMU_PTR_ATTR_NORMAL_MEMORY;

    bottom_page_table[0] = ((uint64_t) second_level[0] >> 12) << 12 | pt_prot;
    top_page_table[511] = ((uint64_t) second_level[1] >> 12) << 12 | pt_prot;

    const uint64_t prot = ARM64_MMU_INNER_SHAREABLE | ARM64_MMU_BLOCK | ARM64_MMU_VALID |
                          ARM64_MMU_AF | MMU_PTR_ATTR_NORMAL_MEMORY;
    second_level[0][0] = 0 | prot;
    second_level[0][1] = 0x40000000 | prot;
    second_level[0][2] = 0x80000000 | prot;
    second_level[0][3] = 0xc0000000 | prot;

    second_level[1][510] = (uint64_t) third_level | pt_prot;

    for (unsigned int i = 0; i < 512; i++)
    {
        third_level[i] = phys_base | prot;
        phys_base += 0x200000;
    }

    msr("mair_el1", MMU_MAIR);
    isb();

    msr("tcr_el1", TCR_EARLY_BOOT);
    isb();

    msr("ttbr0_el1", bottom_page_table);
    msr("ttbr1_el1", top_page_table);
    isb();

    unsigned long sctlr = mrs("sctlr_el1");
    sctlr |= (1 << 0);
    msr("sctlr_el1", sctlr);
    isb();

    // MMU is enabled, trampoline pages are set up for the bottom 4GB, kernel is mapped at the
    // proper location
}
