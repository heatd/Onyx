/*
 * Copyright (c) 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef _ONYX_ARM64_GIC_H
#define _ONYX_ARM64_GIC_H

// Taken from ARM Generic Interrupt Controller Architecture Specification, v2, 4-74 onwards

#define GICD_CTLR          0x0
#define GICD_TYPER         0x4
#define GICD_IIDR          0x8
#define GICD_IGROUPR(n)    (0x080 + ((n) >> 5) * 4)
#define GICD_ISENABLER(n)  (0x100 + ((n) >> 5) * 4)
#define GICD_ICENABLER(n)  (0x180 + ((n) >> 5) * 4)
#define GICD_ISPENDR(n)    (0x200 + ((n) >> 5) * 4)
#define GICD_ICPENDR(n)    (0x280 + ((n) >> 5) * 4)
#define GICD_ISACTIVER(n)  (0x300 + ((n) >> 5) * 4)
#define GICD_ICACTIVER(n)  (0x380 + ((n) >> 5) * 4)
#define GICD_IPRIORITYR(n) (0x400 + ((n) >> 2) * 4)
#define GICD_ITARGETSR(n)  (0x800 + ((n) >> 2) * 4)
#define GICD_ICFGR(n)      (0xc00 + ((n) >> 4) * 4)
#define GICD_SGIR          0xf00
#define GICD_CPENDSGIR     0xf10
#define GICD_SPENDSGIR     0xf20

#define GICC_CTLR     0x0
#define GICC_PMR      0x4
#define GICC_BPR      0x8
#define GICC_IAR      0xc
#define GICC_EOIR     0x10
#define GICC_RPR      0x14
#define GICC_HPPIR    0x18
#define GICC_ABPR     0x1c
#define GICC_AIAR     0x20
#define GICC_AEOIR    0x24
#define GICC_AHPPIR   0x28
#define GICC_APR(n)   0xd0
#define GICC_NSAPR(n) 0xe0
#define GICC_IIDR     0xfc
#define GICC_DIR      0x1000

#define GICD_TYPER_ITLINESNUMBER(typer) (typer & 0b11111)

#define GICD_CTLR_ENABLE (1 << 0)
#define GICC_CTLR_ENABLE (1 << 0)

#endif
