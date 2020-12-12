#
# Copyright (c) 2016, 2017 Pedro Falcato
# This file is part of Onyx, and is released under the terms of the MIT License
# check LICENSE at the root directory for more information
#

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

.section .boot
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
	add $KERNEL_VIRTUAL_BASE, %rdx
	mov %rdx, %r11
	mov %edx, %eax
	shr $32, %rdx
	mov $GS_BASE_MSR, %ecx
	wrmsr

	mov %r11, %gs:__cpu_base

	call multiboot2_kernel_entry
	call _init
	call randomize_stack_canary
	call kernel_main
	cli
_start.Lhang: 
	hlt
	jmp _start.Lhang

.section .boot
protectedmode_stack:
	.skip 128
protectedmode_stack_top:

.code32
.global entry_point
entry_point: 
	cli
	# Clear the direction flag since its state is unspecified by the multiboot spec
	cld
	mov $protectedmode_stack_top, %esp
	pushl %eax
	pushl %ebx
	movl $gdtr1, %eax
	lgdt (%eax)

	pushl $0x08
	push $.gdtrdy
	lret

.gdtrdy: 
	movl $0x10, %eax
	movw %ax, %ds
	movw %ax, %ss
	call setup_paging_and_longm

	movl $gdtr2, %eax
	lgdt (gdtr2)

	pushl $0x08
	push $.gdt2rdy
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

	movq $gdtr3, %rax
	lgdt (%rax)
	popq %rbx
	xorq %rsi, %rsi
	movq %rbx, %rsi
	shrq $32, %rsi

	movq %rbx, %r8
	xorq %rdi, %rdi
	movl %r8d, %edi
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
	mov $pml4, %edi
2:
	movl $pdpt, %eax
	orl $(X86_PAGING_PRESENT | X86_PAGING_WRITE), %eax
	movl %eax, pml4

	PAGE_TABLE_INDEX %esp, 3

	mov $pml4, %esi
	mov %eax, (%esi, %ebx, 8)

	movl $pdlower, %eax
	or $(X86_PAGING_PRESENT | X86_PAGING_WRITE), %eax
	movl %eax, pdpt

	movl $pd, %eax
	or $(X86_PAGING_PRESENT | X86_PAGING_WRITE), %eax

	PAGE_TABLE_INDEX %esp, 2

	mov $pdpt, %esi
	mov %eax, (%esi, %ebx, 8)

	PAGE_TABLE_INDEX %esp, 1

	push %ebx

	mov $pdlower, %esi

	movl $0x000083, %eax
	mov %eax, (%esi, %ebx, 8)
	inc %ebx
	movl $0x200083, %eax
	mov %eax, (%esi, %ebx, 8)
	inc %ebx
	movl $0x400083, %eax
	mov %eax, (%esi, %ebx, 8)

	pop %ebx

	mov $pd, %esi
	movl $0x000083, %eax
	mov %eax, (%esi, %ebx, 8)
	inc %ebx
	movl $0x200083, %eax
	mov %eax, (%esi, %ebx, 8)
	inc %ebx
	movl $0x400083, %eax
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
