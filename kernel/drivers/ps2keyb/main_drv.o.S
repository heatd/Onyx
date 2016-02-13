	.file	"main_drv.cpp"
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
	.globl	_Z15KeyboardHandlerj
	.type	_Z15KeyboardHandlerj, @function
_Z15KeyboardHandlerj:
.LFB7:
	.file 1 "drivers/ps2keyb/main_drv.cpp"
	.loc 1 24 0
	.cfi_startproc
.LVL0:
.LBB18:
.LBB19:
	.file 2 "include/kernel/portio.h"
	.loc 2 35 0
/APP
/  35 "include/kernel/portio.h" 1
	inb $100, %al
/  0 "" 2
.LVL1:
/NO_APP
.LBE19:
.LBE18:
	.loc 1 30 0
	testb	$1, %al
	jne	.L4
	rep ret
	.align 16
.L4:
.LVL2:
.LBB20:
.LBB21:
.LBB22:
.LBB23:
	.loc 2 35 0
/APP
/  35 "include/kernel/portio.h" 1
	inb $96, %al
/  0 "" 2
.LVL3:
/NO_APP
.LBE23:
.LBE22:
	.loc 1 32 0
	movzbl	%al, %eax
	movl	%eax, 4(%esp)
.LVL4:
	jmp	_Z15SendEventToKernh
.LVL5:
.LBE21:
.LBE20:
	.cfi_endproc
.LFE7:
	.size	_Z15KeyboardHandlerj, .-_Z15KeyboardHandlerj
	.section	.text.unlikely
.LCOLDE0:
	.text
.LHOTE0:
	.section	.text.unlikely
.LCOLDB1:
	.text
.LHOTB1:
	.align 16
	.globl	_Z13init_keyboardv
	.type	_Z13init_keyboardv, @function
_Z13init_keyboardv:
.LFB8:
	.loc 1 36 0
	.cfi_startproc
.LVL6:
	subl	$24, %esp
	.cfi_def_cfa_offset 28
	.loc 1 38 0
	pushl	$1
	.cfi_def_cfa_offset 32
	call	_ZN3PIC9UnmaskIRQEt
.LVL7:
	.loc 1 39 0
	popl	%eax
	.cfi_def_cfa_offset 28
	popl	%edx
	.cfi_def_cfa_offset 24
	pushl	$_Z15KeyboardHandlerj
	.cfi_def_cfa_offset 28
	pushl	$1
	.cfi_def_cfa_offset 32
	call	_ZN3IRQ14InstallHandlerEiPFvjE
.LVL8:
	.loc 1 41 0
	xorl	%eax, %eax
	addl	$28, %esp
	.cfi_def_cfa_offset 4
	ret
	.cfi_endproc
.LFE8:
	.size	_Z13init_keyboardv, .-_Z13init_keyboardv
	.section	.text.unlikely
.LCOLDE1:
	.text
.LHOTE1:
.Letext0:
	.section	.text.unlikely
.Letext_cold0:
	.file 3 "include/kernel/irq.h"
	.file 4 "/home/pfalcato/i686-elf/lib/gcc/i686-elf/5.3.0/include/stdint-gcc.h"
	.section	.debug_info,"",@progbits
.Ldebug_info0:
	.long	0x1ef
	.value	0x4
	.long	.Ldebug_abbrev0
	.byte	0x4
	.uleb128 0x1
	.long	.LASF15
	.byte	0x4
	.long	.LASF16
	.long	.LASF17
	.long	.Ldebug_ranges0+0
	.long	0
	.long	.Ldebug_line0
	.uleb128 0x2
	.long	.LASF5
	.byte	0x3
	.byte	0x11
	.long	0x30
	.uleb128 0x3
	.byte	0x4
	.long	0x36
	.uleb128 0x4
	.long	0x41
	.uleb128 0x5
	.long	0x41
	.byte	0
	.uleb128 0x6
	.byte	0x4
	.byte	0x7
	.long	.LASF0
	.uleb128 0x6
	.byte	0x1
	.byte	0x6
	.long	.LASF1
	.uleb128 0x6
	.byte	0x2
	.byte	0x5
	.long	.LASF2
	.uleb128 0x6
	.byte	0x4
	.byte	0x5
	.long	.LASF3
	.uleb128 0x6
	.byte	0x8
	.byte	0x5
	.long	.LASF4
	.uleb128 0x2
	.long	.LASF6
	.byte	0x4
	.byte	0x2e
	.long	0x6f
	.uleb128 0x6
	.byte	0x1
	.byte	0x8
	.long	.LASF7
	.uleb128 0x2
	.long	.LASF8
	.byte	0x4
	.byte	0x31
	.long	0x81
	.uleb128 0x6
	.byte	0x2
	.byte	0x7
	.long	.LASF9
	.uleb128 0x6
	.byte	0x4
	.byte	0x7
	.long	.LASF10
	.uleb128 0x6
	.byte	0x8
	.byte	0x7
	.long	.LASF11
	.uleb128 0x7
	.byte	0x4
	.byte	0x5
	.string	"int"
	.uleb128 0x8
	.string	"inb"
	.byte	0x2
	.byte	0x20
	.long	0x64
	.byte	0x3
	.long	0xc4
	.uleb128 0x9
	.long	.LASF12
	.byte	0x2
	.byte	0x20
	.long	0x76
	.uleb128 0xa
	.string	"ret"
	.byte	0x2
	.byte	0x22
	.long	0x64
	.byte	0
	.uleb128 0xb
	.long	.LASF18
	.byte	0x1
	.byte	0x17
	.long	.LASF19
	.byte	0x1
	.long	0xf6
	.uleb128 0xc
	.string	"eip"
	.byte	0x1
	.byte	0x17
	.long	0x41
	.uleb128 0xd
	.long	.LASF13
	.byte	0x1
	.byte	0x1a
	.long	0x6f
	.uleb128 0xd
	.long	.LASF14
	.byte	0x1
	.byte	0x1b
	.long	0x6f
	.byte	0
	.uleb128 0xe
	.long	0xc4
	.long	.LASF19
	.long	.LFB7
	.long	.LFE7-.LFB7
	.uleb128 0x1
	.byte	0x9c
	.long	0x1a9
	.uleb128 0xf
	.long	0xd4
	.long	.LLST0
	.uleb128 0x10
	.long	0xdf
	.uleb128 0x10
	.long	0xea
	.uleb128 0x11
	.long	0x9d
	.long	.LBB18
	.long	.LBE18-.LBB18
	.byte	0x1
	.byte	0x1c
	.long	0x14c
	.uleb128 0xf
	.long	0xad
	.long	.LLST1
	.uleb128 0x12
	.long	.LBB19
	.long	.LBE19-.LBB19
	.uleb128 0x10
	.long	0xb8
	.byte	0
	.byte	0
	.uleb128 0x12
	.long	.LBB20
	.long	.LBE20-.LBB20
	.uleb128 0xf
	.long	0xd4
	.long	.LLST2
	.uleb128 0x12
	.long	.LBB21
	.long	.LBE21-.LBB21
	.uleb128 0x10
	.long	0xdf
	.uleb128 0x10
	.long	0xea
	.uleb128 0x11
	.long	0x9d
	.long	.LBB22
	.long	.LBE22-.LBB22
	.byte	0x1
	.byte	0x1f
	.long	0x19d
	.uleb128 0xf
	.long	0xad
	.long	.LLST3
	.uleb128 0x12
	.long	.LBB23
	.long	.LBE23-.LBB23
	.uleb128 0x10
	.long	0xb8
	.byte	0
	.byte	0
	.uleb128 0x13
	.long	.LVL5
	.long	0x1e3
	.byte	0
	.byte	0
	.byte	0
	.uleb128 0x14
	.long	.LASF20
	.byte	0x1
	.byte	0x23
	.long	.LASF21
	.long	0x96
	.long	.LFB8
	.long	.LFE8-.LFB8
	.uleb128 0x1
	.byte	0x9c
	.long	0x1e3
	.uleb128 0x15
	.long	.LASF22
	.byte	0x1
	.byte	0x25
	.long	0x25
	.uleb128 0x6
	.byte	0x3
	.long	_Z15KeyboardHandlerj
	.byte	0x9f
	.uleb128 0x16
	.long	.LVL7
	.uleb128 0x16
	.long	.LVL8
	.byte	0
	.uleb128 0x17
	.long	.LASF23
	.long	.LASF24
	.byte	0x1
	.byte	0x15
	.long	.LASF23
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
	.uleb128 0x55
	.uleb128 0x17
	.uleb128 0x11
	.uleb128 0x1
	.uleb128 0x10
	.uleb128 0x17
	.byte	0
	.byte	0
	.uleb128 0x2
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
	.uleb128 0x3
	.uleb128 0xf
	.byte	0
	.uleb128 0xb
	.uleb128 0xb
	.uleb128 0x49
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0x4
	.uleb128 0x15
	.byte	0x1
	.uleb128 0x1
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0x5
	.uleb128 0x5
	.byte	0
	.uleb128 0x49
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0x6
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
	.uleb128 0x7
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
	.uleb128 0x8
	.uleb128 0x2e
	.byte	0x1
	.uleb128 0x3
	.uleb128 0x8
	.uleb128 0x3a
	.uleb128 0xb
	.uleb128 0x3b
	.uleb128 0xb
	.uleb128 0x49
	.uleb128 0x13
	.uleb128 0x20
	.uleb128 0xb
	.uleb128 0x1
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0x9
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
	.byte	0
	.byte	0
	.uleb128 0xa
	.uleb128 0x34
	.byte	0
	.uleb128 0x3
	.uleb128 0x8
	.uleb128 0x3a
	.uleb128 0xb
	.uleb128 0x3b
	.uleb128 0xb
	.uleb128 0x49
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0xb
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
	.uleb128 0x20
	.uleb128 0xb
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
	.byte	0
	.byte	0
	.uleb128 0xd
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
	.byte	0
	.byte	0
	.uleb128 0xe
	.uleb128 0x2e
	.byte	0x1
	.uleb128 0x31
	.uleb128 0x13
	.uleb128 0x6e
	.uleb128 0xe
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
	.uleb128 0xf
	.uleb128 0x5
	.byte	0
	.uleb128 0x31
	.uleb128 0x13
	.uleb128 0x2
	.uleb128 0x17
	.byte	0
	.byte	0
	.uleb128 0x10
	.uleb128 0x34
	.byte	0
	.uleb128 0x31
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0x11
	.uleb128 0x1d
	.byte	0x1
	.uleb128 0x31
	.uleb128 0x13
	.uleb128 0x11
	.uleb128 0x1
	.uleb128 0x12
	.uleb128 0x6
	.uleb128 0x58
	.uleb128 0xb
	.uleb128 0x59
	.uleb128 0xb
	.uleb128 0x1
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0x12
	.uleb128 0xb
	.byte	0x1
	.uleb128 0x11
	.uleb128 0x1
	.uleb128 0x12
	.uleb128 0x6
	.byte	0
	.byte	0
	.uleb128 0x13
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
	.uleb128 0x14
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
	.uleb128 0x49
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
	.uleb128 0x15
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
	.uleb128 0x16
	.uleb128 0x4109
	.byte	0
	.uleb128 0x11
	.uleb128 0x1
	.byte	0
	.byte	0
	.uleb128 0x17
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
	.byte	0
	.section	.debug_loc,"",@progbits
.Ldebug_loc0:
.LLST0:
	.long	.LVL0
	.long	.LVL4
	.value	0x2
	.byte	0x91
	.sleb128 0
	.long	0
	.long	0
.LLST1:
	.long	.LVL0
	.long	.LVL1
	.value	0x3
	.byte	0x8
	.byte	0x64
	.byte	0x9f
	.long	0
	.long	0
.LLST2:
	.long	.LVL2
	.long	.LVL4
	.value	0x2
	.byte	0x91
	.sleb128 0
	.long	0
	.long	0
.LLST3:
	.long	.LVL2
	.long	.LVL3
	.value	0x3
	.byte	0x8
	.byte	0x60
	.byte	0x9f
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
	.section	.debug_ranges,"",@progbits
.Ldebug_ranges0:
	.long	.Ltext0
	.long	.Letext0
	.long	0
	.long	0
	.section	.debug_line,"",@progbits
.Ldebug_line0:
	.section	.debug_str,"MS",@progbits,1
.LASF23:
	.string	"_Z15SendEventToKernh"
.LASF14:
	.string	"keycode"
.LASF13:
	.string	"status"
.LASF15:
	.string	"GNU C++11 5.3.0 -mtune=generic -march=pentiumpro -g -O2 -std=c++11 -ffreestanding -fbuiltin -fstack-protector-strong -fno-exceptions -fno-rtti"
.LASF1:
	.string	"signed char"
.LASF7:
	.string	"unsigned char"
.LASF24:
	.string	"SendEventToKern"
.LASF10:
	.string	"long unsigned int"
.LASF9:
	.string	"short unsigned int"
.LASF21:
	.string	"_Z13init_keyboardv"
.LASF17:
	.string	"/home/pfalcato/Spartix/kernel"
.LASF0:
	.string	"unsigned int"
.LASF11:
	.string	"long long unsigned int"
.LASF6:
	.string	"uint8_t"
.LASF20:
	.string	"init_keyboard"
.LASF19:
	.string	"_Z15KeyboardHandlerj"
.LASF22:
	.string	"handler"
.LASF4:
	.string	"long long int"
.LASF12:
	.string	"port"
.LASF18:
	.string	"KeyboardHandler"
.LASF2:
	.string	"short int"
.LASF8:
	.string	"uint16_t"
.LASF3:
	.string	"long int"
.LASF16:
	.string	"drivers/ps2keyb/main_drv.cpp"
.LASF5:
	.string	"irq_t"
	.ident	"GCC: (GNU) 5.3.0"
