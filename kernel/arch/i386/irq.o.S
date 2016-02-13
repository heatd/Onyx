	.file	"irq.cpp"
	.text
.Ltext0:
	.section	.text.unlikely,"ax",@progbits
.LCOLDB0:
	.text
.LHOTB0:
	.align 16
	.section	.text.unlikely
.Ltext_cold0:
	.text
	.globl	_ZN3IRQ14InstallHandlerEiPFvjE
	.type	_ZN3IRQ14InstallHandlerEiPFvjE, @function
_ZN3IRQ14InstallHandlerEiPFvjE:
.LFB0:
	.file 1 "arch/i386/irq.cpp"
	.loc 1 38 0
	.cfi_startproc
.LVL0:
	.loc 1 39 0
	movl	8(%esp), %edx
	movl	4(%esp), %eax
	movl	%edx, irq_routines(,%eax,4)
	ret
	.cfi_endproc
.LFE0:
	.size	_ZN3IRQ14InstallHandlerEiPFvjE, .-_ZN3IRQ14InstallHandlerEiPFvjE
	.section	.text.unlikely
.LCOLDE0:
	.text
.LHOTE0:
	.section	.text.unlikely
.LCOLDB1:
	.text
.LHOTB1:
	.align 16
	.globl	_ZN3IRQ16UninstallHandlerEi
	.type	_ZN3IRQ16UninstallHandlerEi, @function
_ZN3IRQ16UninstallHandlerEi:
.LFB1:
	.loc 1 42 0
	.cfi_startproc
.LVL1:
	.loc 1 43 0
	movl	4(%esp), %eax
	movl	$0, irq_routines(,%eax,4)
	ret
	.cfi_endproc
.LFE1:
	.size	_ZN3IRQ16UninstallHandlerEi, .-_ZN3IRQ16UninstallHandlerEi
	.section	.text.unlikely
.LCOLDE1:
	.text
.LHOTE1:
	.section	.text.unlikely
.LCOLDB2:
	.text
.LHOTB2:
	.align 16
	.globl	irq_handler
	.type	irq_handler, @function
irq_handler:
.LFB2:
	.loc 1 47 0
	.cfi_startproc
.LVL2:
	pushl	%ebx
	.cfi_def_cfa_offset 8
	.cfi_offset 3, -8
	subl	$8, %esp
	.cfi_def_cfa_offset 16
	.loc 1 47 0
	movl	16(%esp), %ebx
	movl	20(%esp), %edx
	.loc 1 48 0
	movl	irq_routines-128(,%ebx,4), %eax
.LVL3:
	.loc 1 49 0
	testl	%eax, %eax
	je	.L4
	.loc 1 50 0
	subl	$12, %esp
	.cfi_def_cfa_offset 28
	pushl	%edx
	.cfi_def_cfa_offset 32
	call	*%eax
.LVL4:
	addl	$16, %esp
	.cfi_def_cfa_offset 16
.L4:
	.loc 1 52 0
	subl	$32, %ebx
	movzbl	%bl, %ebx
	movl	%ebx, 16(%esp)
	.loc 1 53 0
	addl	$8, %esp
	.cfi_def_cfa_offset 8
	popl	%ebx
	.cfi_restore 3
	.cfi_def_cfa_offset 4
	.loc 1 52 0
	jmp	_ZN3PIC7SendEOIEh
.LVL5:
	.cfi_endproc
.LFE2:
	.size	irq_handler, .-irq_handler
	.section	.text.unlikely
.LCOLDE2:
	.text
.LHOTE2:
	.globl	irq_routines
	.section	.bss
	.align 32
	.type	irq_routines, @object
	.size	irq_routines, 64
irq_routines:
	.zero	64
	.text
.Letext0:
	.section	.text.unlikely
.Letext_cold0:
	.file 2 "/home/pfalcato/i686-elf/lib/gcc/i686-elf/5.3.0/include/stdint-gcc.h"
	.file 3 "include/kernel/irq.h"
	.section	.debug_info,"",@progbits
.Ldebug_info0:
	.long	0x186
	.value	0x4
	.long	.Ldebug_abbrev0
	.byte	0x4
	.uleb128 0x1
	.long	.LASF14
	.byte	0x4
	.long	.LASF15
	.long	.LASF16
	.long	.Ltext0
	.long	.Letext0-.Ltext0
	.long	.Ldebug_line0
	.uleb128 0x2
	.byte	0x1
	.byte	0x6
	.long	.LASF0
	.uleb128 0x2
	.byte	0x2
	.byte	0x5
	.long	.LASF1
	.uleb128 0x2
	.byte	0x4
	.byte	0x5
	.long	.LASF2
	.uleb128 0x2
	.byte	0x8
	.byte	0x5
	.long	.LASF3
	.uleb128 0x2
	.byte	0x1
	.byte	0x8
	.long	.LASF4
	.uleb128 0x2
	.byte	0x2
	.byte	0x7
	.long	.LASF5
	.uleb128 0x3
	.long	.LASF9
	.byte	0x2
	.byte	0x34
	.long	0x5a
	.uleb128 0x2
	.byte	0x4
	.byte	0x7
	.long	.LASF6
	.uleb128 0x2
	.byte	0x8
	.byte	0x7
	.long	.LASF7
	.uleb128 0x4
	.byte	0x4
	.byte	0x5
	.string	"int"
	.uleb128 0x2
	.byte	0x4
	.byte	0x7
	.long	.LASF8
	.uleb128 0x3
	.long	.LASF10
	.byte	0x3
	.byte	0x11
	.long	0x81
	.uleb128 0x5
	.byte	0x4
	.long	0x87
	.uleb128 0x6
	.long	0x92
	.uleb128 0x7
	.long	0x6f
	.byte	0
	.uleb128 0x8
	.string	"IRQ"
	.byte	0x3
	.byte	0x13
	.long	0xc9
	.uleb128 0x9
	.long	.LASF17
	.byte	0x1
	.byte	0x25
	.long	.LASF18
	.long	0xb7
	.uleb128 0x7
	.long	0x68
	.uleb128 0x7
	.long	0x76
	.byte	0
	.uleb128 0xa
	.long	.LASF19
	.byte	0x1
	.byte	0x29
	.long	.LASF20
	.uleb128 0x7
	.long	0x68
	.byte	0
	.byte	0
	.uleb128 0xb
	.long	0x9d
	.long	.LFB0
	.long	.LFE0-.LFB0
	.uleb128 0x1
	.byte	0x9c
	.long	0xf9
	.uleb128 0xc
	.string	"irq"
	.byte	0x1
	.byte	0x25
	.long	0x68
	.uleb128 0x2
	.byte	0x91
	.sleb128 0
	.uleb128 0xd
	.long	.LASF11
	.byte	0x1
	.byte	0x25
	.long	0x76
	.uleb128 0x2
	.byte	0x91
	.sleb128 4
	.byte	0
	.uleb128 0xb
	.long	0xb7
	.long	.LFB1
	.long	.LFE1-.LFB1
	.uleb128 0x1
	.byte	0x9c
	.long	0x11b
	.uleb128 0xc
	.string	"irq"
	.byte	0x1
	.byte	0x29
	.long	0x68
	.uleb128 0x2
	.byte	0x91
	.sleb128 0
	.byte	0
	.uleb128 0xe
	.long	.LASF21
	.byte	0x1
	.byte	0x2e
	.long	.LFB2
	.long	.LFE2-.LFB2
	.uleb128 0x1
	.byte	0x9c
	.long	0x161
	.uleb128 0xd
	.long	.LASF12
	.byte	0x1
	.byte	0x2e
	.long	0x4f
	.uleb128 0x2
	.byte	0x91
	.sleb128 0
	.uleb128 0xc
	.string	"eip"
	.byte	0x1
	.byte	0x2e
	.long	0x6f
	.uleb128 0x2
	.byte	0x91
	.sleb128 4
	.uleb128 0xf
	.long	.LASF11
	.byte	0x1
	.byte	0x30
	.long	0x76
	.long	.LLST0
	.uleb128 0x10
	.long	.LVL5
	.byte	0
	.uleb128 0x11
	.long	0x81
	.long	0x171
	.uleb128 0x12
	.long	0x171
	.byte	0xf
	.byte	0
	.uleb128 0x2
	.byte	0x4
	.byte	0x7
	.long	.LASF13
	.uleb128 0x13
	.long	.LASF22
	.byte	0x1
	.byte	0x1e
	.long	0x161
	.uleb128 0x5
	.byte	0x3
	.long	irq_routines
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
	.uleb128 0xe
	.byte	0
	.byte	0
	.uleb128 0x3
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
	.uleb128 0x4
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
	.uleb128 0x5
	.uleb128 0xf
	.byte	0
	.uleb128 0xb
	.uleb128 0xb
	.uleb128 0x49
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0x6
	.uleb128 0x15
	.byte	0x1
	.uleb128 0x1
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0x7
	.uleb128 0x5
	.byte	0
	.uleb128 0x49
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0x8
	.uleb128 0x39
	.byte	0x1
	.uleb128 0x3
	.uleb128 0x8
	.uleb128 0x3a
	.uleb128 0xb
	.uleb128 0x3b
	.uleb128 0xb
	.uleb128 0x1
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0x9
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
	.uleb128 0x6e
	.uleb128 0xe
	.uleb128 0x3c
	.uleb128 0x19
	.uleb128 0x1
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0xa
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
	.uleb128 0x6e
	.uleb128 0xe
	.uleb128 0x3c
	.uleb128 0x19
	.byte	0
	.byte	0
	.uleb128 0xb
	.uleb128 0x2e
	.byte	0x1
	.uleb128 0x47
	.uleb128 0x13
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
	.uleb128 0xc
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
	.uleb128 0x18
	.byte	0
	.byte	0
	.uleb128 0xd
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
	.uleb128 0xe
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
	.uleb128 0x2116
	.uleb128 0x19
	.uleb128 0x1
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0xf
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
	.uleb128 0x17
	.byte	0
	.byte	0
	.uleb128 0x10
	.uleb128 0x4109
	.byte	0
	.uleb128 0x11
	.uleb128 0x1
	.uleb128 0x2115
	.uleb128 0x19
	.byte	0
	.byte	0
	.uleb128 0x11
	.uleb128 0x1
	.byte	0x1
	.uleb128 0x49
	.uleb128 0x13
	.uleb128 0x1
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0x12
	.uleb128 0x21
	.byte	0
	.uleb128 0x49
	.uleb128 0x13
	.uleb128 0x2f
	.uleb128 0xb
	.byte	0
	.byte	0
	.uleb128 0x13
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
	.uleb128 0x3f
	.uleb128 0x19
	.uleb128 0x2
	.uleb128 0x18
	.byte	0
	.byte	0
	.byte	0
	.section	.debug_loc,"",@progbits
.Ldebug_loc0:
.LLST0:
	.long	.LVL3-.Ltext0
	.long	.LVL4-1-.Ltext0
	.value	0x1
	.byte	0x50
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
.LASF10:
	.string	"irq_t"
.LASF22:
	.string	"irq_routines"
.LASF19:
	.string	"UninstallHandler"
.LASF14:
	.string	"GNU C++11 5.3.0 -mtune=generic -march=pentiumpro -g -O2 -std=c++11 -ffreestanding -fbuiltin -fstack-protector-strong -fno-exceptions -fno-rtti"
.LASF20:
	.string	"_ZN3IRQ16UninstallHandlerEi"
.LASF4:
	.string	"unsigned char"
.LASF6:
	.string	"long unsigned int"
.LASF5:
	.string	"short unsigned int"
.LASF18:
	.string	"_ZN3IRQ14InstallHandlerEiPFvjE"
.LASF21:
	.string	"irq_handler"
.LASF16:
	.string	"/home/pfalcato/Spartix/kernel"
.LASF8:
	.string	"unsigned int"
.LASF7:
	.string	"long long unsigned int"
.LASF17:
	.string	"InstallHandler"
.LASF11:
	.string	"handler"
.LASF13:
	.string	"sizetype"
.LASF3:
	.string	"long long int"
.LASF12:
	.string	"irqn"
.LASF1:
	.string	"short int"
.LASF9:
	.string	"uint32_t"
.LASF2:
	.string	"long int"
.LASF0:
	.string	"signed char"
.LASF15:
	.string	"arch/i386/irq.cpp"
	.ident	"GCC: (GNU) 5.3.0"
