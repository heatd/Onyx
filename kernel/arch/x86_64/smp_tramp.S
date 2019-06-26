/*
* Copyright (c) 2018 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#define SMP_TRAMPOLINE_BASE	0x0
.section .text
.code16
.global _start_smp
.extern smp_done
_start_smp:
	# ensure that interrupts are disabled
	cli
	xor %ax, %ax
	mov %ax, %ds
	mov %ax, %gs
	mov %ax, %fs
	mov %ax, %es
	mov %ax, %ss
	mov %eax, %cr0
	mov $SMP_TRAMPOLINE_BASE + _gdtr_begin - _start_smp, %eax
	lgdt (%eax)
	mov %cr0, %eax
	or $1, %al
	mov %eax, %cr0
	jmp $0x08, $SMP_TRAMPOLINE_BASE + __long_mode_enter - _start_smp
.code32
__long_mode_enter:
	mov $0x10, %ax
	mov %ax, %ds
	mov %ax, %gs
	mov %ax, %fs
	mov %ax, %es
	mov %ax, %ss
	.extern pml4
	# Load the kernel's pml4
	mov $pml4, %eax
	mov %eax, %cr3
	# Enable PAE
	mov %cr4, %eax
	or $1 << 5, %eax
	mov %eax, %cr4
	/* Enable Long Mode in the MSR
	 * Use this to perform some initialization of features
	 * we might need
	*/

	mov $0xC0000080, %ecx
	rdmsr
	or $1, %eax # enable syscall/sysret
	or $1 << 8, %eax # enable long mode
	or $1 << 11, %eax # enable NX
	wrmsr

	# Enable Paging
	mov %cr0, %eax
	or $1 << 31, %eax
	mov %eax, %cr0
	mov $SMP_TRAMPOLINE_BASE + _gdtr2_begin - _start_smp, %eax
	lgdt (%eax)

	mov $stack - _start_smp, %esp
	push $0x08
	push $0x0 + _long_mode - _start_smp
	lret
_long_mode:
.code64
	.extern boot_pml4
	mov boot_pml4, %rax
	mov  $.higher_half, %rbx
	jmp *%rbx
.higher_half:
	.extern gdtr3
	lgdt (gdtr3)
	mov %rax, %cr3
	mov $0x10, %rax
	mov %ax, %ds
	mov %ax, %gs
	mov %ax, %fs
	mov %ax, %es
	mov %ax, %ss

	.extern ap_done
	# Load the shared IDT
	.extern idt_ptr
	lidt (idt_ptr)
	.extern core_stack
	mov (core_stack), %rsp
	mov %cr3, %rax
	mov %rax, %cr3

	mov %cr0, %rax
	and $0xFFFB, %ax
	or $0x2, %ax
	or $1 << 16, %eax
	mov %rax, %cr0
	mov %cr4, %rax
	or $3 << 9, %ax
	or $1 << 18, %eax
	mov %rax, %cr4
	push $0x1F80
	ldmxcsr (%rsp)
	add $8, %rsp
	.extern cpu_num
	mov cpu_num, %rdi
	# Say to the BSP that we finished
	.extern ap_done
	lock incb ap_done
	push $0
	.extern cpu_ap_entry
	push $cpu_ap_entry
	ret
halt:
	hlt
	jmp halt

.align 16
stack:
.skip 2048
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
.section .text
.global __idle
__idle:
	cli
	hlt
	jmp __idle
