/*
 * Copyright (c) 2016 - 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include <onyx/x86/asm.h>

.section .text

ENTRY(tss_flush)
    mov $0x3b, %ax
    ltr %ax
    RET
END(tss_flush)

ENTRY(gdt_flush)
    lgdt (%rdi)
    RET
END(gdt_flush)

ENTRY(idt_flush)
    lidt (%rdi)
    RET
END(idt_flush)
