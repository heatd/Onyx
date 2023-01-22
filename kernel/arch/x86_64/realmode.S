/*
 * Copyright (c) 2018 - 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
#include <onyx/x86/control_regs.h>
#include <onyx/x86/msr.h>
#include <onyx/x86/asm.h>
#include <onyx/x86/segments.h>

#define PHYS_BASE       (0xffffd00000000000)
#define SMP_TRAMPOLINE_BASE	0x0

.section .rodata.realmode
.code16
.global _start_smp
.extern smp_done
_start_smp:
#define SMPSYM(sym) (sym - _start_smp + SMP_TRAMPOLINE_BASE)
    # ensure that interrupts are disabled
    cli
    jmp .skip_data
.global smpboot_header
smpboot_header:
thread_stack_lo: .long 0
thread_stack_hi: .long 0
ap_done:	.quad 0
kernel_load_bias_lo: .long 0
kernel_load_bias_hi: .long 0
.skip_data:
    xor %ax, %ax
    mov %ax, %ds
    mov %ax, %gs
    mov %ax, %fs
    mov %ax, %es
    mov %ax, %ss
    mov %eax, %cr0
    mov $SMPSYM(_gdtr_begin), %eax
    lgdt (%eax)
    mov %cr0, %eax
    or $CR0_PE, %al
    mov %eax, %cr0
    jmp $KERNEL_CS, $SMPSYM(__long_mode_enter)


.code32
__long_mode_enter:
    mov $KERNEL_DS, %ax
    mov %ax, %ds
    mov %ax, %gs
    mov %ax, %fs
    mov %ax, %es
    mov %ax, %ss

    /* Load the kernel's load bias onto ebp */    
    mov SMPSYM(kernel_load_bias_lo), %ebp

    mov SMPSYM(thread_stack_lo), %ecx
    mov SMPSYM(thread_stack_hi), %edx

    /* We're bound to be online in some instructions, might as well just set ap_done and go
     * to generic code. Note that this is safe because we don't touch the smpboot_header again.
     */
    movl $1, SMPSYM(ap_done)

    lea startup_secondary_32(%ebp), %eax
    jmp *%eax
.align 4
stack:
.skip 32
.global _smp_func_end
_smp_func_end:
gdt:
    .quad	0x0000000000000000
    .quad	0x00CF9A000000FFFF
    .quad	0x00CF92000000FFFF

_gdtr_begin:
gdtr:
    .word	40
    .long	0x0 + _smp_func_end - _start_smp
.global _end_smp
_end_smp:
