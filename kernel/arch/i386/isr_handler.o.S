	.file	"isr_handler.cpp"
	.text
.Ltext0:
	.section	.rodata.str1.1,"aMS",@progbits,1
.LC0:
	.string	"Division by zero exception!"
.LC1:
	.string	"Debug Trap!"
.LC2:
	.string	"Hit a breakpoint"
.LC3:
	.string	"Overflow trap"
.LC4:
	.string	"Fault: Bound range exceeded"
	.section	.rodata.str1.4,"aMS",@progbits,1
	.align 4
.LC5:
	.string	"Opcode invalid.The kernel image might be damaged or is running in an unknown or incompatible architecture"
	.section	.rodata.str1.1
.LC6:
	.string	"Device not available"
	.section	.rodata.str1.4
	.align 4
.LC7:
	.string	"Double fault!The kernel is exiting shortly."
	.section	.rodata.str1.1
.LC8:
	.string	"Invalid TSS"
.LC9:
	.string	"Segment not present!"
.LC10:
	.string	"Stack segment fault!"
.LC11:
	.string	"General Protection Fault"
.LC12:
	.string	"\nSegment %X\n"
.LC13:
	.string	"GPF"
.LC14:
	.string	"Page fault at 0x%x\n"
.LC15:
	.string	"Details: "
.LC16:
	.string	"Present,"
	.section	.rodata.str1.4
	.align 4
.LC17:
	.string	" write-access caused the fault,"
	.align 4
.LC18:
	.string	" read-access caused the fault,"
	.section	.rodata.str1.1
.LC19:
	.string	"user mode"
.LC20:
	.string	"kernel-mode"
.LC21:
	.string	"x87 floating point exception!"
.LC22:
	.string	"SIMD Floating-point exception"
.LC23:
	.string	"Virtualization exception!"
	.section	.text.unlikely,"ax",@progbits
.LCOLDB24:
	.text
.LHOTB24:
	.align 16
	.section	.text.unlikely
.Ltext_cold0:
	.text
	.globl	isr_handler
	.type	isr_handler, @function
isr_handler:
.LFB0:
	.file 1 "arch/i386/isr_handler.cpp"
	.loc 1 21 0
	.cfi_startproc
.LVL0:
	pushl	%ebx
	.cfi_def_cfa_offset 8
	.cfi_offset 3, -8
	subl	$8, %esp
	.cfi_def_cfa_offset 16
	.loc 1 21 0
	movl	20(%esp), %eax
	movl	24(%esp), %ebx
	.loc 1 22 0
	cmpl	$20, %eax
	ja	.L1
	jmp	*.L4(,%eax,4)
	.section	.rodata
	.align 4
	.align 4
.L4:
	.long	.L3
	.long	.L5
	.long	.L1
	.long	.L6
	.long	.L7
	.long	.L8
	.long	.L9
	.long	.L10
	.long	.L11
	.long	.L1
	.long	.L12
	.long	.L13
	.long	.L14
	.long	.L15
	.long	.L16
	.long	.L1
	.long	.L17
	.long	.L1
	.long	.L1
	.long	.L18
	.long	.L19
	.text
	.align 16
.L18:
	.loc 1 119 0
	movl	$.LC22, 16(%esp)
.LVL1:
	.loc 1 139 0
	addl	$8, %esp
	.cfi_remember_state
	.cfi_def_cfa_offset 8
	popl	%ebx
	.cfi_restore 3
	.cfi_def_cfa_offset 4
	.loc 1 119 0
	jmp	printf
.LVL2:
	.align 16
.L1:
	.cfi_restore_state
	.loc 1 139 0
	addl	$8, %esp
	.cfi_remember_state
	.cfi_def_cfa_offset 8
	popl	%ebx
	.cfi_restore 3
	.cfi_def_cfa_offset 4
	ret
	.align 16
.L3:
	.cfi_restore_state
	.loc 1 25 0
	subl	$12, %esp
	.cfi_remember_state
	.cfi_def_cfa_offset 28
	pushl	$.LC0
	.cfi_def_cfa_offset 32
	call	_Z5panicPKc
.LVL3:
	.align 16
.L5:
	.cfi_restore_state
	.loc 1 29 0
	subl	$12, %esp
	.cfi_remember_state
	.cfi_def_cfa_offset 28
	pushl	$.LC1
	.cfi_def_cfa_offset 32
	call	_Z5panicPKc
.LVL4:
	.align 16
.L17:
	.cfi_restore_state
	.loc 1 109 0
	movl	$.LC21, 16(%esp)
.LVL5:
	.loc 1 139 0
	addl	$8, %esp
	.cfi_remember_state
	.cfi_def_cfa_offset 8
	popl	%ebx
	.cfi_restore 3
	.cfi_def_cfa_offset 4
	.loc 1 109 0
	jmp	printf
.LVL6:
	.align 16
.L6:
	.cfi_restore_state
	.loc 1 36 0
	movl	$.LC2, 16(%esp)
.LVL7:
	.loc 1 139 0
	addl	$8, %esp
	.cfi_remember_state
	.cfi_def_cfa_offset 8
	popl	%ebx
	.cfi_restore 3
	.cfi_def_cfa_offset 4
	.loc 1 36 0
	jmp	printf
.LVL8:
	.align 16
.L7:
	.cfi_restore_state
	.loc 1 40 0
	movl	$.LC3, 16(%esp)
.LVL9:
	.loc 1 139 0
	addl	$8, %esp
	.cfi_remember_state
	.cfi_def_cfa_offset 8
	popl	%ebx
	.cfi_restore 3
	.cfi_def_cfa_offset 4
	.loc 1 40 0
	jmp	printf
.LVL10:
	.align 16
.L8:
	.cfi_restore_state
	.loc 1 44 0
	movl	$.LC4, 16(%esp)
.LVL11:
	.loc 1 139 0
	addl	$8, %esp
	.cfi_remember_state
	.cfi_def_cfa_offset 8
	popl	%ebx
	.cfi_restore 3
	.cfi_def_cfa_offset 4
	.loc 1 44 0
	jmp	printf
.LVL12:
	.align 16
.L9:
	.cfi_restore_state
	.loc 1 48 0
	subl	$12, %esp
	.cfi_remember_state
	.cfi_def_cfa_offset 28
	pushl	$.LC5
	.cfi_def_cfa_offset 32
	call	_Z5panicPKc
.LVL13:
	.align 16
.L10:
	.cfi_restore_state
	.loc 1 52 0
	movl	$.LC6, 16(%esp)
.LVL14:
	.loc 1 139 0
	addl	$8, %esp
	.cfi_remember_state
	.cfi_def_cfa_offset 8
	popl	%ebx
	.cfi_restore 3
	.cfi_def_cfa_offset 4
	.loc 1 52 0
	jmp	printf
.LVL15:
	.align 16
.L11:
	.cfi_restore_state
	.loc 1 56 0
	subl	$12, %esp
	.cfi_remember_state
	.cfi_def_cfa_offset 28
	pushl	$.LC7
	.cfi_def_cfa_offset 32
	call	_Z5panicPKc
.LVL16:
	.align 16
.L19:
	.cfi_restore_state
	.loc 1 123 0
	movl	$.LC23, 16(%esp)
.LVL17:
	.loc 1 139 0
	addl	$8, %esp
	.cfi_remember_state
	.cfi_def_cfa_offset 8
	popl	%ebx
	.cfi_restore 3
	.cfi_def_cfa_offset 4
	.loc 1 123 0
	jmp	printf
.LVL18:
	.align 16
.L12:
	.cfi_restore_state
	.loc 1 63 0
	subl	$12, %esp
	.cfi_remember_state
	.cfi_def_cfa_offset 28
	pushl	$.LC8
	.cfi_def_cfa_offset 32
	call	_Z5panicPKc
.LVL19:
	.align 16
.L13:
	.cfi_restore_state
	.loc 1 67 0
	subl	$12, %esp
	.cfi_remember_state
	.cfi_def_cfa_offset 28
	pushl	$.LC9
	.cfi_def_cfa_offset 32
	call	_Z5panicPKc
.LVL20:
	.align 16
.L14:
	.cfi_restore_state
	.loc 1 71 0
	subl	$12, %esp
	.cfi_remember_state
	.cfi_def_cfa_offset 28
	pushl	$.LC10
	.cfi_def_cfa_offset 32
	call	_Z5panicPKc
.LVL21:
	.align 16
.L15:
	.cfi_restore_state
	.loc 1 75 0
	subl	$12, %esp
	.cfi_def_cfa_offset 28
	pushl	$.LC11
	.cfi_def_cfa_offset 32
	call	printf
.LVL22:
	.loc 1 76 0
	addl	$16, %esp
	.cfi_def_cfa_offset 16
	testl	%ebx, %ebx
	jne	.L35
.L20:
	.loc 1 78 0
	subl	$12, %esp
	.cfi_remember_state
	.cfi_def_cfa_offset 28
	pushl	$.LC13
	.cfi_def_cfa_offset 32
	call	_Z5panicPKc
.LVL23:
	.align 16
.L16:
	.cfi_restore_state
	.loc 1 84 0
/APP
/  84 "arch/i386/isr_handler.cpp" 1
	mov %cr2, %eax
/  0 "" 2
	.loc 1 88 0
/NO_APP
	subl	$8, %esp
	.cfi_def_cfa_offset 24
	.loc 1 84 0
	movl	%eax, _ZL16faulting_address
	.loc 1 88 0
	pushl	%eax
	.cfi_def_cfa_offset 28
	pushl	$.LC14
	.cfi_def_cfa_offset 32
	call	printf
.LVL24:
	.loc 1 89 0
	movl	$.LC15, (%esp)
	call	printf
.LVL25:
	.loc 1 90 0
	addl	$16, %esp
	.cfi_def_cfa_offset 16
	testb	$2, %bl
	jne	.L36
.L21:
	.loc 1 93 0
	testb	$4, %bl
	je	.L22
	.loc 1 94 0
	subl	$12, %esp
	.cfi_def_cfa_offset 28
	pushl	$.LC17
	.cfi_def_cfa_offset 32
	call	printf
.LVL26:
	addl	$16, %esp
	.cfi_def_cfa_offset 16
.L23:
	.loc 1 98 0
	andl	$8, %ebx
	je	.L24
	.loc 1 99 0
	subl	$12, %esp
	.cfi_def_cfa_offset 28
	pushl	$.LC19
	.cfi_def_cfa_offset 32
	call	printf
.LVL27:
	addl	$16, %esp
	.cfi_def_cfa_offset 16
.L25:
.L32:
	jmp	.L32
	.align 16
.L24:
	.loc 1 101 0
	subl	$12, %esp
	.cfi_def_cfa_offset 28
	pushl	$.LC20
	.cfi_def_cfa_offset 32
	call	puts
.LVL28:
	addl	$16, %esp
	.cfi_def_cfa_offset 16
	jmp	.L25
	.align 16
.L22:
	.loc 1 96 0
	subl	$12, %esp
	.cfi_def_cfa_offset 28
	pushl	$.LC18
	.cfi_def_cfa_offset 32
	call	printf
.LVL29:
	addl	$16, %esp
	.cfi_def_cfa_offset 16
	jmp	.L23
.L36:
	.loc 1 91 0
	subl	$12, %esp
	.cfi_def_cfa_offset 28
	pushl	$.LC16
	.cfi_def_cfa_offset 32
	call	printf
.LVL30:
	addl	$16, %esp
	.cfi_def_cfa_offset 16
	jmp	.L21
.L35:
	.loc 1 77 0
	subl	$8, %esp
	.cfi_def_cfa_offset 24
	pushl	%ebx
	.cfi_def_cfa_offset 28
	pushl	$.LC12
	.cfi_def_cfa_offset 32
	call	printf
.LVL31:
	addl	$16, %esp
	.cfi_def_cfa_offset 16
	jmp	.L20
	.cfi_endproc
.LFE0:
	.size	isr_handler, .-isr_handler
	.section	.text.unlikely
.LCOLDE24:
	.text
.LHOTE24:
	.local	_ZL16faulting_address
	.comm	_ZL16faulting_address,4,4
.Letext0:
	.section	.text.unlikely
.Letext_cold0:
	.file 2 "/home/pfalcato/i686-elf/lib/gcc/i686-elf/5.3.0/include/stdint-gcc.h"
	.file 3 "/home/pfalcato/Spartix/sysroot/usr/include/stdio.h"
	.file 4 "include/kernel/panic.h"
	.section	.debug_info,"",@progbits
.Ldebug_info0:
	.long	0x1c3
	.value	0x4
	.long	.Ldebug_abbrev0
	.byte	0x4
	.uleb128 0x1
	.long	.LASF11
	.byte	0x4
	.long	.LASF12
	.long	.LASF13
	.long	.Ltext0
	.long	.Letext0-.Ltext0
	.long	.Ldebug_line0
	.uleb128 0x2
	.byte	0x4
	.byte	0x5
	.string	"int"
	.uleb128 0x3
	.byte	0x1
	.byte	0x6
	.long	.LASF0
	.uleb128 0x3
	.byte	0x2
	.byte	0x5
	.long	.LASF1
	.uleb128 0x3
	.byte	0x4
	.byte	0x5
	.long	.LASF2
	.uleb128 0x3
	.byte	0x8
	.byte	0x5
	.long	.LASF3
	.uleb128 0x3
	.byte	0x1
	.byte	0x8
	.long	.LASF4
	.uleb128 0x3
	.byte	0x2
	.byte	0x7
	.long	.LASF5
	.uleb128 0x4
	.long	.LASF14
	.byte	0x2
	.byte	0x34
	.long	0x61
	.uleb128 0x3
	.byte	0x4
	.byte	0x7
	.long	.LASF6
	.uleb128 0x3
	.byte	0x8
	.byte	0x7
	.long	.LASF7
	.uleb128 0x3
	.byte	0x4
	.byte	0x7
	.long	.LASF8
	.uleb128 0x5
	.long	.LASF15
	.byte	0x1
	.byte	0x14
	.long	.LFB0
	.long	.LFE0-.LFB0
	.uleb128 0x1
	.byte	0x9c
	.long	0x18e
	.uleb128 0x6
	.string	"ds"
	.byte	0x1
	.byte	0x14
	.long	0x56
	.long	.LLST0
	.uleb128 0x7
	.long	.LASF9
	.byte	0x1
	.byte	0x14
	.long	0x56
	.uleb128 0x2
	.byte	0x91
	.sleb128 4
	.uleb128 0x7
	.long	.LASF10
	.byte	0x1
	.byte	0x14
	.long	0x56
	.uleb128 0x2
	.byte	0x91
	.sleb128 8
	.uleb128 0x8
	.long	.LVL2
	.long	0x19f
	.uleb128 0x9
	.long	.LVL3
	.long	0x1aa
	.uleb128 0x9
	.long	.LVL4
	.long	0x1aa
	.uleb128 0x8
	.long	.LVL6
	.long	0x19f
	.uleb128 0x8
	.long	.LVL8
	.long	0x19f
	.uleb128 0x8
	.long	.LVL10
	.long	0x19f
	.uleb128 0x8
	.long	.LVL12
	.long	0x19f
	.uleb128 0x9
	.long	.LVL13
	.long	0x1aa
	.uleb128 0x8
	.long	.LVL15
	.long	0x19f
	.uleb128 0x9
	.long	.LVL16
	.long	0x1aa
	.uleb128 0x8
	.long	.LVL18
	.long	0x19f
	.uleb128 0x9
	.long	.LVL19
	.long	0x1aa
	.uleb128 0x9
	.long	.LVL20
	.long	0x1aa
	.uleb128 0x9
	.long	.LVL21
	.long	0x1aa
	.uleb128 0x9
	.long	.LVL22
	.long	0x19f
	.uleb128 0x9
	.long	.LVL23
	.long	0x1aa
	.uleb128 0x9
	.long	.LVL24
	.long	0x19f
	.uleb128 0x9
	.long	.LVL25
	.long	0x19f
	.uleb128 0x9
	.long	.LVL26
	.long	0x19f
	.uleb128 0x9
	.long	.LVL27
	.long	0x19f
	.uleb128 0x9
	.long	.LVL28
	.long	0x1b9
	.uleb128 0x9
	.long	.LVL29
	.long	0x19f
	.uleb128 0x9
	.long	.LVL30
	.long	0x19f
	.uleb128 0x9
	.long	.LVL31
	.long	0x19f
	.byte	0
	.uleb128 0xa
	.long	.LASF16
	.byte	0x1
	.byte	0x13
	.long	0x56
	.uleb128 0x5
	.byte	0x3
	.long	_ZL16faulting_address
	.uleb128 0xb
	.long	.LASF17
	.long	.LASF17
	.byte	0x3
	.byte	0x18
	.uleb128 0xc
	.long	.LASF18
	.long	.LASF19
	.byte	0x4
	.byte	0x1a
	.long	.LASF18
	.uleb128 0xd
	.long	.LASF20
	.long	.LASF21
	.long	.LASF20
	.byte	0
	.section	.debug_abbrev,"",@progbits
.Ldebug_abbrev0:
	.uleb128 0x1
	.uleb128 0x11
	.byte	0x1
	.uleb128 0x25
	.uleb128 0xe
	.uleb128 0x13
	.uleb128 0xb
	.uleb128 0x3
	.uleb128 0xe
	.uleb128 0x1b
	.uleb128 0xe
	.uleb128 0x11
	.uleb128 0x1
	.uleb128 0x12
	.uleb128 0x6
	.uleb128 0x10
	.uleb128 0x17
	.byte	0
	.byte	0
	.uleb128 0x2
	.uleb128 0x24
	.byte	0
	.uleb128 0xb
	.uleb128 0xb
	.uleb128 0x3e
	.uleb128 0xb
	.uleb128 0x3
	.uleb128 0x8
	.byte	0
	.byte	0
	.uleb128 0x3
	.uleb128 0x24
	.byte	0
	.uleb128 0xb
	.uleb128 0xb
	.uleb128 0x3e
	.uleb128 0xb
	.uleb128 0x3
	.uleb128 0xe
	.byte	0
	.byte	0
	.uleb128 0x4
	.uleb128 0x16
	.byte	0
	.uleb128 0x3
	.uleb128 0xe
	.uleb128 0x3a
	.uleb128 0xb
	.uleb128 0x3b
	.uleb128 0xb
	.uleb128 0x49
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0x5
	.uleb128 0x2e
	.byte	0x1
	.uleb128 0x3f
	.uleb128 0x19
	.uleb128 0x3
	.uleb128 0xe
	.uleb128 0x3a
	.uleb128 0xb
	.uleb128 0x3b
	.uleb128 0xb
	.uleb128 0x11
	.uleb128 0x1
	.uleb128 0x12
	.uleb128 0x6
	.uleb128 0x40
	.uleb128 0x18
	.uleb128 0x2117
	.uleb128 0x19
	.uleb128 0x1
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0x6
	.uleb128 0x5
	.byte	0
	.uleb128 0x3
	.uleb128 0x8
	.uleb128 0x3a
	.uleb128 0xb
	.uleb128 0x3b
	.uleb128 0xb
	.uleb128 0x49
	.uleb128 0x13
	.uleb128 0x2
	.uleb128 0x17
	.byte	0
	.byte	0
	.uleb128 0x7
	.uleb128 0x5
	.byte	0
	.uleb128 0x3
	.uleb128 0xe
	.uleb128 0x3a
	.uleb128 0xb
	.uleb128 0x3b
	.uleb128 0xb
	.uleb128 0x49
	.uleb128 0x13
	.uleb128 0x2
	.uleb128 0x18
	.byte	0
	.byte	0
	.uleb128 0x8
	.uleb128 0x4109
	.byte	0
	.uleb128 0x11
	.uleb128 0x1
	.uleb128 0x2115
	.uleb128 0x19
	.uleb128 0x31
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0x9
	.uleb128 0x4109
	.byte	0
	.uleb128 0x11
	.uleb128 0x1
	.uleb128 0x31
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0xa
	.uleb128 0x34
	.byte	0
	.uleb128 0x3
	.uleb128 0xe
	.uleb128 0x3a
	.uleb128 0xb
	.uleb128 0x3b
	.uleb128 0xb
	.uleb128 0x49
	.uleb128 0x13
	.uleb128 0x2
	.uleb128 0x18
	.byte	0
	.byte	0
	.uleb128 0xb
	.uleb128 0x2e
	.byte	0
	.uleb128 0x3f
	.uleb128 0x19
	.uleb128 0x3c
	.uleb128 0x19
	.uleb128 0x6e
	.uleb128 0xe
	.uleb128 0x3
	.uleb128 0xe
	.uleb128 0x3a
	.uleb128 0xb
	.uleb128 0x3b
	.uleb128 0xb
	.byte	0
	.byte	0
	.uleb128 0xc
	.uleb128 0x2e
	.byte	0
	.uleb128 0x3f
	.uleb128 0x19
	.uleb128 0x3c
	.uleb128 0x19
	.uleb128 0x6e
	.uleb128 0xe
	.uleb128 0x3
	.uleb128 0xe
	.uleb128 0x3a
	.uleb128 0xb
	.uleb128 0x3b
	.uleb128 0xb
	.uleb128 0x6e
	.uleb128 0xe
	.byte	0
	.byte	0
	.uleb128 0xd
	.uleb128 0x2e
	.byte	0
	.uleb128 0x3f
	.uleb128 0x19
	.uleb128 0x3c
	.uleb128 0x19
	.uleb128 0x6e
	.uleb128 0xe
	.uleb128 0x3
	.uleb128 0xe
	.uleb128 0x6e
	.uleb128 0xe
	.byte	0
	.byte	0
	.byte	0
	.section	.debug_loc,"",@progbits
.Ldebug_loc0:
.LLST0:
	.long	.LVL0-.Ltext0
	.long	.LVL1-.Ltext0
	.value	0x2
	.byte	0x91
	.sleb128 0
	.long	.LVL2-.Ltext0
	.long	.LVL5-.Ltext0
	.value	0x2
	.byte	0x91
	.sleb128 0
	.long	.LVL6-.Ltext0
	.long	.LVL7-.Ltext0
	.value	0x2
	.byte	0x91
	.sleb128 0
	.long	.LVL8-.Ltext0
	.long	.LVL9-.Ltext0
	.value	0x2
	.byte	0x91
	.sleb128 0
	.long	.LVL10-.Ltext0
	.long	.LVL11-.Ltext0
	.value	0x2
	.byte	0x91
	.sleb128 0
	.long	.LVL12-.Ltext0
	.long	.LVL14-.Ltext0
	.value	0x2
	.byte	0x91
	.sleb128 0
	.long	.LVL15-.Ltext0
	.long	.LVL17-.Ltext0
	.value	0x2
	.byte	0x91
	.sleb128 0
	.long	.LVL18-.Ltext0
	.long	.LFE0-.Ltext0
	.value	0x2
	.byte	0x91
	.sleb128 0
	.long	0
	.long	0
	.section	.debug_aranges,"",@progbits
	.long	0x1c
	.value	0x2
	.long	.Ldebug_info0
	.byte	0x4
	.byte	0
	.value	0
	.value	0
	.long	.Ltext0
	.long	.Letext0-.Ltext0
	.long	0
	.long	0
	.section	.debug_line,"",@progbits
.Ldebug_line0:
	.section	.debug_str,"MS",@progbits,1
.LASF19:
	.string	"panic"
.LASF11:
	.string	"GNU C++11 5.3.0 -mtune=generic -march=pentiumpro -g -O2 -std=c++11 -ffreestanding -fbuiltin -fstack-protector-strong -fno-exceptions -fno-rtti"
.LASF4:
	.string	"unsigned char"
.LASF12:
	.string	"arch/i386/isr_handler.cpp"
.LASF6:
	.string	"long unsigned int"
.LASF5:
	.string	"short unsigned int"
.LASF16:
	.string	"faulting_address"
.LASF13:
	.string	"/home/pfalcato/Spartix/kernel"
.LASF8:
	.string	"unsigned int"
.LASF7:
	.string	"long long unsigned int"
.LASF9:
	.string	"int_no"
.LASF15:
	.string	"isr_handler"
.LASF3:
	.string	"long long int"
.LASF10:
	.string	"err_code"
.LASF17:
	.string	"printf"
.LASF1:
	.string	"short int"
.LASF14:
	.string	"uint32_t"
.LASF2:
	.string	"long int"
.LASF20:
	.string	"puts"
.LASF0:
	.string	"signed char"
.LASF18:
	.string	"_Z5panicPKc"
.LASF21:
	.string	"__builtin_puts"
	.ident	"GCC: (GNU) 5.3.0"
