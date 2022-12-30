/*
 * Copyright (c) 2018 - 2022 Pedro Falcato
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
thread_stack:	.quad 0		# To be filled by the waking up code
gs_base:	.quad 0
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
    .extern pml4
    # Load the kernel's pml4
    mov SMPSYM(kernel_load_bias_lo), %ebp
    lea pml4(%ebp), %eax
    mov %eax, %cr3
    # Enable PAE and PSE
    mov %cr4, %eax
    or $(CR4_PAE | CR4_PSE), %eax
    mov %eax, %cr4

    /* Enable Long Mode in the MSR
     * Use this to enable NX as well */

    mov $IA32_EFER, %ecx
    rdmsr
    or $(IA32_EFER_LME | IA32_EFER_NXE), %eax
    xorl %edx, %edx
    wrmsr

    # Enable Paging and write protect
    mov %cr0, %eax
    or $(CR0_PG | CR0_WP), %eax
    mov %eax, %cr0
    mov $SMPSYM(_gdtr2_begin), %eax
    lgdt (%eax)

    mov $SMPSYM(stack), %esp
    push $KERNEL_CS
    push $SMPSYM(_long_mode)
    lret
_long_mode:
.code64
    .extern boot_pml4
    mov boot_pml4, %rax
    mov  $.higher_half, %rbx
    jmp *%rbx
.higher_half:
    .extern gdtr3
    lea gdtr3(%ebp), %rbx
    lgdt (%rbx)
    mov %rax, %cr3
    mov $KERNEL_DS, %rax
    mov %ax, %ds
    mov %ax, %es
    mov %ax, %ss
    xor %ax, %ax
    mov %ax, %gs
    mov %ax, %fs

    # Load the shared IDT
    .extern idt_ptr
    lidt (idt_ptr)
#undef SMPSYM
#define SMPSYM(sym) (sym - _start_smp + SMP_TRAMPOLINE_BASE)(%r11)
    mov $PHYS_BASE, %r11
    mov SMPSYM(thread_stack), %rsp
    mov %cr3, %rax
    mov %rax, %cr3

    mov SMPSYM(gs_base), %rdi

    lea SMPSYM(smpboot_header), %rsi

    /* Note: This cannot be done in C++ code because LTO likes to get funky and add stack protector stuff where
     * there wasn't any, when inlining. This caused a mov %gs:0x28, reg to exist before the
     * wrmsr and init_ssp_for_cpu.
     */
    /* Take the time to wrmsr the gs base, before we enter any C/C++ code */
    mov %rdi, %rdx
    mov %rdx, %r11
    mov %edx, %eax
    shr $32, %rdx
    mov $GS_BASE_MSR, %ecx
    wrmsr

    push %rdi
    push %rsi

    /* And call init_ssp_for_cpu too! */
    movl %gs:cpu_nr, %edi
    call init_ssp_for_cpu

    pop %rsi
    pop %rdi
#undef SMPSYM

    .extern smpboot_main
    push $smpboot_main
    RET
halt:
    hlt
    jmp halt

.align 4
stack:
.skip 32
.global _smp_func_end
_smp_func_end:
gdt:
    .quad	0x0000000000000000
    .quad	0x00CF9A000000FFFF
    .quad	0x00CF92000000FFFF
gdtl:
    .quad 	0x0000000000000000
    .quad	0x00A09A0000000000
    .quad	0x00A0920000000000
    .quad	0x00A0FA0000000000
    .quad	0x00A0F20000000000
tss_gdt:
    .word	0x67,0
    .byte	0, 0xE9, 0
    .byte	0
    .long	0

_gdtr_begin:
gdtr:
    .word	40
    .long	0x0 + _smp_func_end - _start_smp
_gdtr2_begin:
gdtr2:
    .word 40
    .long 0x0 + gdtl - _start_smp
.global _end_smp
_end_smp:
