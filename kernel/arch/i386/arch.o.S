	.file	"arch.cpp"
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
	.globl	_Z9init_archv
	.type	_Z9init_archv, @function
_Z9init_archv:
.LFB0:
	.file 1 "arch/i386/arch.cpp"
	.loc 1 31 0
	.cfi_startproc
	subl	$12, %esp
	.cfi_def_cfa_offset 16
	.loc 1 32 0
	call	init_sse
.LVL0:
	.loc 1 34 0
	call	_Z8init_gdtv
.LVL1:
	.loc 1 36 0
	call	_Z8init_idtv
.LVL2:
	.loc 1 39 0
	addl	$12, %esp
	.cfi_def_cfa_offset 4
	.loc 1 38 0
	jmp	_ZN3PIC5RemapEv
.LVL3:
	.cfi_endproc
.LFE0:
	.size	_Z9init_archv, .-_Z9init_archv
	.section	.text.unlikely
.LCOLDE0:
	.text
.LHOTE0:
.Letext0:
	.section	.text.unlikely
.Letext_cold0:
	.file 2 "include/kernel/gdt.h"
	.file 3 "include/kernel/idt.h"
	.section	.debug_info,"",@progbits
.Ldebug_info0:
	.long	0xcb
	.value	0x4
	.long	.Ldebug_abbrev0
	.byte	0x4
	.uleb128 0x1
	.long	.LASF13
	.byte	0x4
	.long	.LASF14
	.long	.LASF15
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
	.uleb128 0x4
	.long	.LASF16
	.byte	0x1
	.byte	0x1e
	.long	.LASF17
	.long	.LFB0
	.long	.LFE0-.LFB0
	.uleb128 0x1
	.byte	0x9c
	.long	0xa5
	.uleb128 0x5
	.long	.LVL0
	.long	0xa5
	.uleb128 0x5
	.long	.LVL1
	.long	0xb0
	.uleb128 0x5
	.long	.LVL2
	.long	0xbf
	.uleb128 0x6
	.long	.LVL3
	.byte	0
	.uleb128 0x7
	.long	.LASF18
	.long	.LASF18
	.byte	0x1
	.byte	0x1d
	.uleb128 0x8
	.long	.LASF9
	.long	.LASF11
	.byte	0x2
	.byte	0x46
	.long	.LASF9
	.uleb128 0x8
	.long	.LASF10
	.long	.LASF12
	.byte	0x3
	.byte	0x29
	.long	.LASF10
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
	.uleb128 0x5
	.uleb128 0x4109
	.byte	0
	.uleb128 0x11
	.uleb128 0x1
	.uleb128 0x31
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0x6
	.uleb128 0x4109
	.byte	0
	.uleb128 0x11
	.uleb128 0x1
	.uleb128 0x2115
	.uleb128 0x19
	.byte	0
	.byte	0
	.uleb128 0x7
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
	.uleb128 0x8
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
.LASF3:
	.string	"long long int"
.LASF8:
	.string	"unsigned int"
.LASF11:
	.string	"init_gdt"
.LASF12:
	.string	"init_idt"
.LASF15:
	.string	"/home/pfalcato/Spartix/kernel"
.LASF6:
	.string	"long unsigned int"
.LASF9:
	.string	"_Z8init_gdtv"
.LASF7:
	.string	"long long unsigned int"
.LASF18:
	.string	"init_sse"
.LASF10:
	.string	"_Z8init_idtv"
.LASF4:
	.string	"unsigned char"
.LASF2:
	.string	"long int"
.LASF14:
	.string	"arch/i386/arch.cpp"
.LASF5:
	.string	"short unsigned int"
.LASF0:
	.string	"signed char"
.LASF17:
	.string	"_Z9init_archv"
.LASF16:
	.string	"init_arch"
.LASF1:
	.string	"short int"
.LASF13:
	.string	"GNU C++11 5.3.0 -mtune=generic -march=pentiumpro -g -O2 -std=c++11 -ffreestanding -fbuiltin -fstack-protector-strong -fno-exceptions -fno-rtti"
	.ident	"GCC: (GNU) 5.3.0"
