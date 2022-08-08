/*
 * Copyright (c) 2016 - 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */


#include <onyx/x86/control_regs.h>
#include <onyx/x86/msr.h>

#define KERNEL_VIRTUAL_BASE     0xffffffff80000000
#define X86_PAGING_PRESENT		(1 << 0)
#define X86_PAGING_WRITE		(1 << 1)
#define X86_PAGING_USER			(1 << 2)
#define X86_PAGING_WRITETHROUGH		(1 << 3)
#define X86_PAGING_PCD			(1 << 4)
#define X86_PAGING_ACCESSED		(1 << 5)
#define X86_PAGING_DIRTY		(1 << 6)
#define X86_PAGING_PAT			(1 << 7)
#define X86_PAGING_HUGE			(1 << 7)
#define X86_PAGING_GLOBAL		(1 << 8)
#define X86_PAGING_NX			(1 << 63)

.section .boot, "aw"
jmp entry_point
.align 4
hdr_start: 
	.long 0xe85250d6
	.long 0
	.long hdr_end - hdr_start
	.long 0x100000000 - (0xe85250d6 + 0 + (hdr_end - hdr_start))
	.align 8 # All tags need to be 8 byte aligned
	# Framebuffer tag
	.word 5
	.word 0
	.long 20
	.long 1024
	.long 768
	.long 32
	.align 8
	# Module alignment tag
	.word 6
	.word 0
	.long 8
#ifdef CONFIG_RELOCATABLE_PHYS
	.align 8
	.word 10
	.word 0
	.long 24
	/* Use a minimum address of 1MB, a max of 4GB, alignment of 2MB (so we can easily map ourselves) */
	.long 0x100000
	.long 0xffffffff
	.long 0x200000
	/* 2 = put us as high as you can */
	.long 2
#endif
	.align 8
	# Finish tag
	.word 0
	.word 0
	.long 8
hdr_end: 

.section .bss

.align 16

stack_bottom:
.skip 16384

stack_top:

.section .text
_start:
	push $0
	movq $stack_top, %rsp

	/* Take the time to wrmsr the default GS_BASE */
	mov $percpu_base, %rdx
	mov %rdx, %r11
	mov %edx, %eax
	shr $32, %rdx
	mov $GS_BASE_MSR, %ecx
	wrmsr

	mov %r11, %gs:__cpu_base

	call multiboot2_kernel_entry
	call _init
	call runtime_call_constructors
	# rdi = cpu nr
	xor %rdi, %rdi
	call init_ssp_for_cpu
	call kernel_main
	cli
_start.Lhang: 
	hlt
	jmp _start.Lhang

.section .boot, "aw"
protectedmode_stack:
	.skip 128
protectedmode_stack_top:

#ifdef CONFIG_RELOCATABLE_PHYS
#define CALC_EFF_ADDRESS(label, reg) lea label(%ebp), reg
#else
#define CALC_EFF_ADDRESS(label, reg) mov $label, reg
#endif

.code32
.global entry_point
entry_point:
	cli
#ifdef CONFIG_RELOCATABLE_PHYS
	/* Calculate a possible load bias */
	call 1f
1:
	pop %edi
	movl $1b, %ebp
	sub %ebp, %edi
	mov %edi, %ebp
#else
	xor %ebp, %ebp
#endif
	/* From now on, ebp = load bias */
	# Clear the direction flag since its state is unspecified by the multiboot spec
	cld
	CALC_EFF_ADDRESS(protectedmode_stack_top, %esp)
	pushl %eax
	pushl %ebx
	CALC_EFF_ADDRESS(gdtr1, %eax)
	# Fix up the gdtr before loading it
	CALC_EFF_ADDRESS(gdt, %ebx)
	mov %ebx, 2(%eax)
	lgdt (%eax)

	pushl $0x08
	CALC_EFF_ADDRESS(.gdtrdy, %eax)

	push %eax
	lret

.gdtrdy: 
	movl $0x10, %eax
	movw %ax, %ds
	movw %ax, %ss
	call setup_paging_and_longm

	CALC_EFF_ADDRESS(gdtr2, %eax)
	/* Fixup the gdtr2's gdt address */
	CALC_EFF_ADDRESS(gdt_begin, %edi)
	mov %edi, 2(%eax)
	lgdt (%eax)

	pushl $0x08
	CALC_EFF_ADDRESS(.gdt2rdy, %eax)
	push %eax
	lret

.code64
.gdt2rdy:
	movl $0x10, %eax
	movw %ax, %ds
	movw %ax, %es
	movw %ax, %ss

	# Our %gs and %fs segments need to be NULL
	xor %ax, %ax
	mov %ax, %gs
	mov %ax, %fs

	lea gdtr3(%rip), %rax
	lgdt (%rax)
	popq %rbx
	xorq %rsi, %rsi
	movq %rbx, %rsi
	shrq $32, %rsi

	movq %rbx, %r8
	xorq %rdi, %rdi
	movl %r8d, %edi
#ifdef CONFIG_RELOCATABLE_PHYS
	mov %rbp, kernel_phys_offset
#endif
	movq $_start, %rax
	jmp *%rax

.code32

.macro PAGE_TABLE_INDEX source_ptr, level

mov $\level * 9, %cl
mov 4(\source_ptr), %esi
mov (\source_ptr), %ebx
shrdl %esi, %ebx
and $0x1ff, %ebx

.endm

setup_paging_and_longm:
	/* Register allocation:
	 * edi - Top level page table
	 * 
	 * Usual register allocation for the rest of the code:
	 * eax - Page table entry
	 * ecx - Page table index
	 * edx - shift amount
	 *
	 * Stack allocation:
	 * [off 0] = virtual pfn low
	 * [off 4] =  virtual pfn high
	 */

	sub $8, %esp
	# Index formula: (virt >> 12) >> (pt_level * 9) & 0x1ff;

	mov $KERNEL_VIRTUAL_BASE >> 32, %ebx
	movl $KERNEL_VIRTUAL_BASE, %ecx
	shrdl $12, %ebx, %ecx
	shr $12, %ebx
	mov %ecx, (%esp)
	mov %ebx, 4(%esp)

	/* The top page level is held in %edi */
	/* Test for PML5 */
	mov $7, %eax
	xor %ecx, %ecx
	cpuid
	test $1 << 16, %ecx
	jz 1f

	/* Enable PML5 on cr4 and set a flag */
	mov %cr4, %eax
	or $1 << 12, %eax
	mov %eax, %cr4
	mov $pml5, %edi

	jmp 2f
1:
	CALC_EFF_ADDRESS(pml4, %edi)
2:
	CALC_EFF_ADDRESS(pdpt, %eax)
	orl $(X86_PAGING_PRESENT | X86_PAGING_WRITE), %eax
	movl %eax, (%edi)

	PAGE_TABLE_INDEX %esp, 3

	CALC_EFF_ADDRESS(pml4, %esi)
	mov %eax, (%esi, %ebx, 8)

	CALC_EFF_ADDRESS(pdlower, %eax)
	or $(X86_PAGING_PRESENT | X86_PAGING_WRITE), %eax
	CALC_EFF_ADDRESS(pdpt, %esi)
	movl %eax, (%esi)

	CALC_EFF_ADDRESS(pd, %eax)
	or $(X86_PAGING_PRESENT | X86_PAGING_WRITE), %eax

	PAGE_TABLE_INDEX %esp, 2

	CALC_EFF_ADDRESS(pdpt, %esi)
	mov %eax, (%esi, %ebx, 8)

	PAGE_TABLE_INDEX %esp, 1

	push %ebx

	CALC_EFF_ADDRESS(pdlower, %esi)
3:

	mov %ebx, %eax
	shl $21, %eax
	or $0x83, %eax
	mov %eax, (%esi, %ebx, 8)
	inc %ebx
	cmp $511, %ebx
	jne 3b

	pop %ebx

	CALC_EFF_ADDRESS(pd, %esi)
	movl %ebp, %eax
	or $0x83, %eax
	mov %eax, (%esi, %ebx, 8)
	inc %ebx
	lea 0x200000(%ebp), %eax
	or $0x83, %eax
	mov %eax, (%esi, %ebx, 8)
	inc %ebx
	lea 0x400000(%ebp), %eax
	or $0x83, %eax
	mov %eax, (%esi, %ebx, 8)

	# Load CR3 with the top page level
	movl %edi, %cr3

	# Enable PAE
	movl %cr4, %eax
	or $CR4_PAE, %eax
	movl %eax, %cr4

	# Enable Long Mode in the MSR
	# Use this to enable NX as well
	movl $IA32_EFER, %ecx
	rdmsr
	or $(IA32_EFER_LME | IA32_EFER_NXE), %eax
	xorl %edx, %edx
	wrmsr

	# Enable Paging and write protect
	movl %cr0, %eax
	or $(CR0_PG | CR0_WP), %eax
	movl %eax, %cr0

	add $8, %esp

	ret
gdt: 
	.quad 0x0000000000000000
	.quad 0x00CF9A000000FFFF
	.quad 0x00CF92000000FFFF
.global gdt_begin
gdt_begin: 
	.quad 0x0000000000000000   # 0x0  - NULL segment
	.quad 0x00A09A0000000000   # 0x8  - KERNEL CS
	.quad 0x00A0920000000000   # 0x10 - KERNEL DS
	.quad 0x00CFFA000000FFFF   # 0x18 - 32-bit user CS
	.quad 0x00CFF2000000FFFF   # 0x20 - 32-bit user DS
	.quad 0x00A0FA0000000000   # 0x28 - USER CS
	.quad 0x00A0F20000000000   # 0x30 - USER DS
                               # 0x38 - TSS
tss_gdt: 
	.quad 0
	.quad 0
.global gdt_end
gdt_end:

gdtr1: 
	.word gdt_begin - gdt - 1
	.long gdt

gdtr2: 
	.word gdt_end - gdt_begin - 1
	.long gdt_begin
	.long 0

.global gdtr3
gdtr3: 
	.word gdt_end - gdt_begin - 1
	.quad gdt_begin + 0xFFFFFFFF80000000

.bss
.skip 4096
