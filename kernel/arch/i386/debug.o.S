	.file	"debug.cpp"
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
	.globl	_Z14get_thread_ctxP9registers
	.type	_Z14get_thread_ctxP9registers, @function
_Z14get_thread_ctxP9registers:
.LFB0:
	.file 1 "arch/i386/debug.cpp"
	.loc 1 29 0
	.cfi_startproc
.LVL0:
	.loc 1 29 0
	movl	4(%esp), %edx
	.loc 1 30 0
/APP
/  30 "arch/i386/debug.cpp" 1
	mov %eax,%eax
/  0 "" 2
/NO_APP
	movl	%eax, (%edx)
	.loc 1 31 0
/APP
/  31 "arch/i386/debug.cpp" 1
	mov %ebx,%eax
/  0 "" 2
/NO_APP
	movl	%eax, 4(%edx)
	.loc 1 32 0
/APP
/  32 "arch/i386/debug.cpp" 1
	mov %ecx,%eax
/  0 "" 2
/NO_APP
	movl	%eax, 8(%edx)
	.loc 1 33 0
/APP
/  33 "arch/i386/debug.cpp" 1
	mov %edx,%eax
/  0 "" 2
/NO_APP
	movl	%eax, 12(%edx)
	.loc 1 34 0
/APP
/  34 "arch/i386/debug.cpp" 1
	mov %edi,%eax
/  0 "" 2
/NO_APP
	movl	%eax, 16(%edx)
	.loc 1 35 0
/APP
/  35 "arch/i386/debug.cpp" 1
	mov %ebp,%eax
/  0 "" 2
/NO_APP
	movl	%eax, 28(%edx)
	.loc 1 36 0
/APP
/  36 "arch/i386/debug.cpp" 1
	mov %esp,%eax
/  0 "" 2
/NO_APP
	movl	%eax, 24(%edx)
	.loc 1 37 0
	movl	(%esp), %eax
	movl	%eax, 32(%edx)
	.loc 1 38 0
/APP
/  38 "arch/i386/debug.cpp" 1
	mov %esi,%eax
/  0 "" 2
/NO_APP
	movl	%eax, 20(%edx)
	.loc 1 39 0
/APP
/  39 "arch/i386/debug.cpp" 1
	mov %cs,%ax
/  0 "" 2
/NO_APP
	movw	%ax, 42(%edx)
	.loc 1 40 0
/APP
/  40 "arch/i386/debug.cpp" 1
	mov %ss,%ax
/  0 "" 2
/NO_APP
	movw	%ax, 40(%edx)
	ret
	.cfi_endproc
.LFE0:
	.size	_Z14get_thread_ctxP9registers, .-_Z14get_thread_ctxP9registers
	.section	.text.unlikely
.LCOLDE0:
	.text
.LHOTE0:
	.section	.text.unlikely
.LCOLDB1:
.LHOTB1:
	.globl	_Z4haltv
	.type	_Z4haltv, @function
_Z4haltv:
.LFB1:
	.loc 1 44 0
	.cfi_startproc
	.loc 1 46 0
/APP
/  46 "arch/i386/debug.cpp" 1
	cli
/  0 "" 2
	.loc 1 47 0
/  47 "arch/i386/debug.cpp" 1
	hlt
/  0 "" 2
/NO_APP
.L3:
	jmp	.L3
	.cfi_endproc
.LFE1:
	.size	_Z4haltv, .-_Z4haltv
.LCOLDE1:
.LHOTE1:
	.text
.Letext0:
	.section	.text.unlikely
.Letext_cold0:
	.file 2 "/home/pfalcato/i686-elf/lib/gcc/i686-elf/5.3.0/include/stdint-gcc.h"
	.file 3 "include/kernel/registers.h"
	.section	.debug_info,"",@progbits
.Ldebug_info0:
	.long	0x167
	.value	0x4
	.long	.Ldebug_abbrev0
	.byte	0x4
	.uleb128 0x1
	.long	.LASF13
	.byte	0x4
	.long	.LASF14
	.long	.LASF15
	.long	.Ldebug_ranges0+0
	.long	0
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
	.uleb128 0x3
	.long	.LASF6
	.byte	0x2
	.byte	0x31
	.long	0x53
	.uleb128 0x2
	.byte	0x2
	.byte	0x7
	.long	.LASF5
	.uleb128 0x3
	.long	.LASF7
	.byte	0x2
	.byte	0x34
	.long	0x65
	.uleb128 0x2
	.byte	0x4
	.byte	0x7
	.long	.LASF8
	.uleb128 0x2
	.byte	0x8
	.byte	0x7
	.long	.LASF9
	.uleb128 0x4
	.byte	0x4
	.byte	0x5
	.string	"int"
	.uleb128 0x2
	.byte	0x4
	.byte	0x7
	.long	.LASF10
	.uleb128 0x5
	.long	.LASF16
	.byte	0x2c
	.byte	0x3
	.byte	0x1b
	.long	0x11c
	.uleb128 0x6
	.string	"eax"
	.byte	0x3
	.byte	0x1d
	.long	0x5a
	.byte	0
	.uleb128 0x6
	.string	"ebx"
	.byte	0x3
	.byte	0x1d
	.long	0x5a
	.byte	0x4
	.uleb128 0x6
	.string	"ecx"
	.byte	0x3
	.byte	0x1d
	.long	0x5a
	.byte	0x8
	.uleb128 0x6
	.string	"edx"
	.byte	0x3
	.byte	0x1d
	.long	0x5a
	.byte	0xc
	.uleb128 0x6
	.string	"edi"
	.byte	0x3
	.byte	0x1d
	.long	0x5a
	.byte	0x10
	.uleb128 0x6
	.string	"esi"
	.byte	0x3
	.byte	0x1d
	.long	0x5a
	.byte	0x14
	.uleb128 0x6
	.string	"esp"
	.byte	0x3
	.byte	0x1d
	.long	0x5a
	.byte	0x18
	.uleb128 0x6
	.string	"ebp"
	.byte	0x3
	.byte	0x1d
	.long	0x5a
	.byte	0x1c
	.uleb128 0x6
	.string	"eip"
	.byte	0x3
	.byte	0x1d
	.long	0x5a
	.byte	0x20
	.uleb128 0x7
	.long	.LASF11
	.byte	0x3
	.byte	0x1d
	.long	0x5a
	.byte	0x24
	.uleb128 0x6
	.string	"ss"
	.byte	0x3
	.byte	0x1e
	.long	0x48
	.byte	0x28
	.uleb128 0x6
	.string	"cs"
	.byte	0x3
	.byte	0x1e
	.long	0x48
	.byte	0x2a
	.byte	0
	.uleb128 0x3
	.long	.LASF12
	.byte	0x3
	.byte	0x1f
	.long	0x81
	.uleb128 0x8
	.long	.LASF17
	.byte	0x1
	.byte	0x1c
	.long	.LASF18
	.long	.LFB0
	.long	.LFE0-.LFB0
	.uleb128 0x1
	.byte	0x9c
	.long	0x14f
	.uleb128 0x9
	.long	.LASF19
	.byte	0x1
	.byte	0x1c
	.long	0x14f
	.uleb128 0x2
	.byte	0x91
	.sleb128 0
	.byte	0
	.uleb128 0xa
	.byte	0x4
	.long	0x11c
	.uleb128 0xb
	.long	.LASF20
	.byte	0x1
	.byte	0x2b
	.long	.LASF21
	.long	.LFB1
	.long	.LFE1-.LFB1
	.uleb128 0x1
	.byte	0x9c
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
	.uleb128 0x13
	.byte	0x1
	.uleb128 0x3
	.uleb128 0xe
	.uleb128 0xb
	.uleb128 0xb
	.uleb128 0x3a
	.uleb128 0xb
	.uleb128 0x3b
	.uleb128 0xb
	.uleb128 0x1
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0x6
	.uleb128 0xd
	.byte	0
	.uleb128 0x3
	.uleb128 0x8
	.uleb128 0x3a
	.uleb128 0xb
	.uleb128 0x3b
	.uleb128 0xb
	.uleb128 0x49
	.uleb128 0x13
	.uleb128 0x38
	.uleb128 0xb
	.byte	0
	.byte	0
	.uleb128 0x7
	.uleb128 0xd
	.byte	0
	.uleb128 0x3
	.uleb128 0xe
	.uleb128 0x3a
	.uleb128 0xb
	.uleb128 0x3b
	.uleb128 0xb
	.uleb128 0x49
	.uleb128 0x13
	.uleb128 0x38
	.uleb128 0xb
	.byte	0
	.byte	0
	.uleb128 0x8
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
	.uleb128 0x2
	.uleb128 0x18
	.byte	0
	.byte	0
	.uleb128 0xa
	.uleb128 0xf
	.byte	0
	.uleb128 0xb
	.uleb128 0xb
	.uleb128 0x49
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0xb
	.uleb128 0x2e
	.byte	0
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
	.uleb128 0x87
	.uleb128 0x19
	.uleb128 0x11
	.uleb128 0x1
	.uleb128 0x12
	.uleb128 0x6
	.uleb128 0x40
	.uleb128 0x18
	.uleb128 0x2117
	.uleb128 0x19
	.byte	0
	.byte	0
	.byte	0
	.section	.debug_aranges,"",@progbits
	.long	0x24
	.value	0x2
	.long	.Ldebug_info0
	.byte	0x4
	.byte	0
	.value	0
	.value	0
	.long	.Ltext0
	.long	.Letext0-.Ltext0
	.long	.Ltext_cold0
	.long	.Letext_cold0-.Ltext_cold0
	.long	0
	.long	0
	.section	.debug_ranges,"",@progbits
.Ldebug_ranges0:
	.long	.Ltext0
	.long	.Letext0
	.long	.Ltext_cold0
	.long	.Letext_cold0
	.long	0
	.long	0
	.section	.debug_line,"",@progbits
.Ldebug_line0:
	.section	.debug_str,"MS",@progbits,1
.LASF17:
	.string	"get_thread_ctx"
.LASF20:
	.string	"halt"
.LASF14:
	.string	"arch/i386/debug.cpp"
.LASF18:
	.string	"_Z14get_thread_ctxP9registers"
.LASF13:
	.string	"GNU C++11 5.3.0 -mtune=generic -march=pentiumpro -g -O2 -std=c++11 -ffreestanding -fbuiltin -fstack-protector-strong -fno-exceptions -fno-rtti"
.LASF4:
	.string	"unsigned char"
.LASF8:
	.string	"long unsigned int"
.LASF5:
	.string	"short unsigned int"
.LASF15:
	.string	"/home/pfalcato/Spartix/kernel"
.LASF21:
	.string	"_Z4haltv"
.LASF10:
	.string	"unsigned int"
.LASF9:
	.string	"long long unsigned int"
.LASF19:
	.string	"regs"
.LASF12:
	.string	"registers_t"
.LASF11:
	.string	"eflags"
.LASF3:
	.string	"long long int"
.LASF1:
	.string	"short int"
.LASF6:
	.string	"uint16_t"
.LASF7:
	.string	"uint32_t"
.LASF2:
	.string	"long int"
.LASF0:
	.string	"signed char"
.LASF16:
	.string	"registers"
	.ident	"GCC: (GNU) 5.3.0"
