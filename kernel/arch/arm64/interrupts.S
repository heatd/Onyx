/*
 * Copyright (c) 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

.section .text

.global arm64_exception_vector_table
.balign 0x800
arm64_exception_vector_table:
curr_el0_sp0_sync:
    wfi
.balign 0x80
curr_el0_sp0_irq:
    wfi
.balign 0x80
curr_el0_sp0_fiq:
    wfi
.balign 0x80
curr_el0_sp0_serror:
    wfi
.balign 0x80
curr_el0_spx_sync:
    wfi
.balign 0x80
curr_el0_spx_irq:
    wfi
.balign 0x80
curr_el0_spx_fiq:
    wfi
.balign 0x80
curr_el0_spx_serror:
    wfi
.balign 0x80
lower_el_a64_spx_sync:
    wfi
.balign 0x80
lower_el_a64_spx_irq:
    wfi
.balign 0x80
lower_el_a64_spx_fiq:
    wfi
.balign 0x80
lower_el_a64_spx_serror:
    wfi
lower_el_a32_spx_sync:
    wfi
.balign 0x80
lower_el_a32_spx_irq:
    wfi
.balign 0x80
lower_el_a32_spx_fiq:
    wfi
.balign 0x80
lower_el_a32_spx_serror:
    wfi
