/*
 * Copyright (c) 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef _ONYX_ARM64_MMU_H
#define _ONYX_ARM64_MMU_H

#define ARM64_MMU_VALID           (1UL << 0)
#define ARM64_MMU_TABLE           (1UL << 1)
#define ARM64_MMU_PAGE            (1UL << 1)
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
#define ARM64_MMU_READ_ONLY       (1 << 7)
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

#endif
