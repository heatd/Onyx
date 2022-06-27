/*
 * Copyright (c) 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#include <stdint.h>

#define ARM64_MMU_VALID           (1UL << 0)
#define ARM64_MMU_TABLE           (1UL << 1)
#define ARM64_MMU_BLOCK           (0 << 1)
#define ARM64_MMU_XN              (1UL << 54)
#define ARM64_MMU_PXN             (1UL << 53)
#define ARM64_MMU_CONTIGUOUS      (1UL << 52)
#define ARM64_MMU_DBM             (1UL << 51)
#define ARM64_MMU_nG              (1UL << 11)
#define ARM64_MMU_AF              (1UL << 10)
#define ARM64_MMU_NON_SHAREABLE   (0 << 8)
#define ARM64_MMU_OUTER_SHAREABLE (1 << 9)
#define ARM64_MMU_INNER_SHAREABLE (3 << 8)
#define ARM64_MMU_WRITEABLE       (1 << 7)
#define ARM64_MMU_EL0             (1 << 6)

#define ADDRESS_SPACE_SIZE_SHIFT 48

#define TCR_T0SZ(bitness)             (64 - bitness) // Size of the address space
#define TCR_EPD0                      (1 << 7)       // Disable page table walks for TTBR0
#define TCR_IRGN0_WRITE_BACK_ALLOCATE (1 << 8)
#define TCR_ORGN0_WRITE_BACK_ALLOCATE (1 << 10)
#define TCR_SH0_INNER_SHAREABLE       (3 << 12)
#define TCR_TG0_4KB_GRANULE           (0 << 14) // 4KB granule for the TTBR
#define TCR_T1SZ(bitness)             ((64 - bitness) << 16)
#define TCR_A1                        (1 << 22) // If 1, the ASID is defined by TTBR1
#define TCR_EPD1                      (1 << 23) // Disable page table walks for TTBR1
#define TCR_IRGN1_WRITE_BACK_ALLOCATE (1 << 24)
#define TCR_ORGN1_WRITE_BACK_ALLOCATE (1 << 26)
#define TCR_SH1_INNER_SHAREABLE       (3 << 28)
#define TCR_TG1_4KB_GRANULE           (0 << 30) // 4KB granule for the TTBR
#define TCR_IPS_40_BITS               (2UL << 32)
#define TCR_IPS_ASID_SIZE_16_BIT      (1UL << 36)
#define TCR_TBI0                      (1UL << 37) // Top byte ignore
#define TCR_TBI1                      (1UL << 38)
#define TCR_HA                        (1UL << 39) // Hardware access flag (investigate)
#define TCR_HD                        (1UL << 40) // Hardware dirty flag (investigate)
#define TCR_HPD0                      (1UL << 41) // Disable hierarchical permissions for page tables
#define TCR_HPD1                      (1UL << 41) // Disable hierarchical permissions for page tables

#define TCR_KERNEL_TTBR1                                                            \
    (TCR_T1SZ(48) | TCR_IRGN1_WRITE_BACK_ALLOCATE | TCR_ORGN1_WRITE_BACK_ALLOCATE | \
     TCR_SH1_INNER_SHAREABLE | TCR_TG1_4KB_GRANULE)

#define TCR_IDENTITY_MAPPING_TTBR0                                                  \
    (TCR_T0SZ(48) | TCR_IRGN0_WRITE_BACK_ALLOCATE | TCR_ORGN0_WRITE_BACK_ALLOCATE | \
     TCR_SH0_INNER_SHAREABLE | TCR_TG0_4KB_GRANULE)

#define TCR_IPS (TCR_IPS_40_BITS | TCR_IPS_ASID_SIZE_16_BIT)

#define TCR_EARLY_BOOT (TCR_IPS | TCR_IDENTITY_MAPPING_TTBR0 | TCR_KERNEL_TTBR1)

#define MMU_MAIR_ATTR(index, value) ((value) << (index * 8))

// Device-nGnRnE
#define MMU_MAIR_ATTR0                MMU_MAIR_ATTR(0, 0)
#define MMU_PTE_ATTR_STRONGLY_ORDERED (0 << 2)
// Device-nGnRE
#define MMU_MAIR_ATTR1                MMU_MAIR_ATTR(1, 0x4)
#define MMU_PTE_ATTR_DEVICE           (1 << 2)

// Normal memory
#define MMU_MAIR_ATTR2             MMU_MAIR_ATTR(2, 0xff)
#define MMU_PTR_ATTR_NORMAL_MEMORY (2 << 2)

// Normal memory, uncached, write combining
#define MMU_MAIR_ATTR3               MMU_MAIR_ATTR(2, 0x44)
#define MMU_PTR_ATTR_NORMAL_UNCACHED (3 << 2)

#define MMU_MAIR_ATTR4 0
#define MMU_MAIR_ATTR5 0
#define MMU_MAIR_ATTR6 0
#define MMU_MAIR_ATTR7 0

#define MMU_MAIR                                                                          \
    (MMU_MAIR_ATTR0 | MMU_MAIR_ATTR1 | MMU_MAIR_ATTR2 | MMU_MAIR_ATTR3 | MMU_MAIR_ATTR4 | \
     MMU_MAIR_ATTR5 | MMU_MAIR_ATTR6 | MMU_MAIR_ATTR7)

#define msr(reg, value) ({ __asm__ __volatile__("msr " reg ", %0" ::"r"((unsigned long) value)); })
#define isb()           __asm__ __volatile__("isb" ::: "memory")

#define mrs(reg)                                         \
    ({                                                   \
        unsigned long val;                               \
        __asm__ __volatile__("mrs %0," reg : "=r"(val)); \
        val;                                             \
    })

__attribute__((section(".boot"))) __attribute__((no_sanitize("undefined"))) void arm64_setup_mmu(
    uint64_t *boot_page_tables, uint64_t phys_base)
{
    phys_base &= ~(0x200000 - 1);
    uint64_t *top_page_table = &boot_page_tables[512];
    uint64_t *bottom_page_table = boot_page_tables;
    uint64_t *second_level[2] = {&boot_page_tables[512UL * 2], &boot_page_tables[512UL * 3]};
    uint64_t *third_level = &boot_page_tables[512UL * 4];

    bottom_page_table[0] =
        ((uint64_t) second_level[0] >> 12) << 12 | ARM64_MMU_TABLE | ARM64_MMU_VALID;
    top_page_table[511] =
        ((uint64_t) second_level[1] >> 12) << 12 | ARM64_MMU_TABLE | ARM64_MMU_VALID;

    const uint64_t prot = ARM64_MMU_WRITEABLE | ARM64_MMU_INNER_SHAREABLE | ARM64_MMU_BLOCK |
                          ARM64_MMU_VALID | ARM64_MMU_AF | MMU_PTR_ATTR_NORMAL_MEMORY;
    second_level[0][0] = 0 | prot;
    second_level[0][1] = 0x40000000 | prot;
    second_level[0][2] = 0x80000000 | prot;
    second_level[0][3] = 0xc0000000 | prot;

    second_level[1][510] = (uint64_t) third_level | ARM64_MMU_WRITEABLE |
                           ARM64_MMU_INNER_SHAREABLE | ARM64_MMU_TABLE | ARM64_MMU_VALID;

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
