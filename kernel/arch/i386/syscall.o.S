	.file	"syscall.cpp"
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
	.globl	syscall
	.type	syscall, @function
syscall:
.LFB16:
	.file 1 "arch/i386/syscall.cpp"
	.loc 1 33 0
	.cfi_startproc
	.loc 1 35 0
/APP
/  35 "arch/i386/syscall.cpp" 1
	mov %eax,%eax
/  0 "" 2
/NO_APP
	movl	%eax, %edx
.LVL0:
	.loc 1 36 0
/APP
/  36 "arch/i386/syscall.cpp" 1
	mov %ebx,%eax
/  0 "" 2
.LVL1:
/NO_APP
	movl	%eax, %ecx
.LVL2:
	.loc 1 37 0
/APP
/  37 "arch/i386/syscall.cpp" 1
	mov %ecx,%eax
/  0 "" 2
.LVL3:
	.loc 1 38 0
/  38 "arch/i386/syscall.cpp" 1
	mov %edx,%eax
/  0 "" 2
.LVL4:
	.loc 1 39 0
/  39 "arch/i386/syscall.cpp" 1
	mov %edi,%eax
/  0 "" 2
.LVL5:
	.loc 1 41 0
/NO_APP
	testl	%edx, %edx
	je	.L8
	.loc 1 47 0
	ret
	.align 16
.L8:
	.loc 1 33 0
	subl	$24, %esp
	.cfi_def_cfa_offset 28
	.loc 1 43 0
	pushl	%ecx
	.cfi_def_cfa_offset 32
	call	_ZN3TTY11WriteStringEPKc
.LVL6:
	.loc 1 47 0
	addl	$28, %esp
	.cfi_def_cfa_offset 4
	ret
	.cfi_endproc
.LFE16:
	.size	syscall, .-syscall
	.section	.text.unlikely
.LCOLDE0:
	.text
.LHOTE0:
.Letext0:
	.section	.text.unlikely
.Letext_cold0:
	.file 2 "include/kernel/pmm.h"
	.file 3 "include/kernel/vmm.h"
	.file 4 "/home/pfalcato/i686-elf/lib/gcc/i686-elf/5.3.0/include/stdint-gcc.h"
	.section	.debug_info,"",@progbits
.Ldebug_info0:
	.long	0xea
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
	.long	.LASF14
	.byte	0x4
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
	.uleb128 0x2
	.byte	0xc
	.byte	0x4
	.long	.LASF9
	.uleb128 0x5
	.long	.LASF15
	.uleb128 0x6
	.string	"PMM"
	.byte	0x2
	.byte	0xb
	.uleb128 0x6
	.string	"VMM"
	.byte	0x3
	.byte	0x16
	.uleb128 0x2
	.byte	0x4
	.byte	0x7
	.long	.LASF10
	.uleb128 0x7
	.long	.LASF16
	.byte	0x1
	.byte	0x20
	.long	.LFB16
	.long	.LFE16-.LFB16
	.uleb128 0x1
	.byte	0x9c
	.uleb128 0x8
	.string	"eax"
	.byte	0x1
	.byte	0x22
	.long	0x4f
	.long	.LLST0
	.uleb128 0x8
	.string	"ebx"
	.byte	0x1
	.byte	0x22
	.long	0x4f
	.long	.LLST1
	.uleb128 0x9
	.string	"ecx"
	.byte	0x1
	.byte	0x22
	.long	0x4f
	.uleb128 0x9
	.string	"edx"
	.byte	0x1
	.byte	0x22
	.long	0x4f
	.uleb128 0x9
	.string	"edi"
	.byte	0x1
	.byte	0x22
	.long	0x4f
	.uleb128 0xa
	.long	.LVL6
	.byte	0
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
	.uleb128 0x3b
	.byte	0
	.uleb128 0x3
	.uleb128 0xe
	.byte	0
	.byte	0
	.uleb128 0x6
	.uleb128 0x39
	.byte	0
	.uleb128 0x3
	.uleb128 0x8
	.uleb128 0x3a
	.uleb128 0xb
	.uleb128 0x3b
	.uleb128 0xb
	.byte	0
	.byte	0
	.uleb128 0x7
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
	.byte	0
	.byte	0
	.uleb128 0x8
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
	.uleb128 0x2
	.uleb128 0x17
	.byte	0
	.byte	0
	.uleb128 0x9
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
	.uleb128 0xa
	.uleb128 0x4109
	.byte	0
	.uleb128 0x11
	.uleb128 0x1
	.byte	0
	.byte	0
	.byte	0
	.section	.debug_loc,"",@progbits
.Ldebug_loc0:
.LLST0:
	.long	.LVL0-.Ltext0
	.long	.LVL1-.Ltext0
	.value	0x1
	.byte	0x50
	.long	.LVL1-.Ltext0
	.long	.LVL6-1-.Ltext0
	.value	0x1
	.byte	0x52
	.long	0
	.long	0
.LLST1:
	.long	.LVL2-.Ltext0
	.long	.LVL3-.Ltext0
	.value	0x1
	.byte	0x50
	.long	.LVL3-.Ltext0
	.long	.LVL6-1-.Ltext0
	.value	0x1
	.byte	0x51
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
.LASF16:
	.string	"syscall"
.LASF15:
	.string	"decltype(nullptr)"
.LASF11:
	.string	"GNU C++11 5.3.0 -mtune=generic -march=pentiumpro -g -O2 -std=c++11 -ffreestanding -fbuiltin -fstack-protector-strong -fno-exceptions -fno-rtti"
.LASF4:
	.string	"unsigned char"
.LASF6:
	.string	"long unsigned int"
.LASF5:
	.string	"short unsigned int"
.LASF13:
	.string	"/home/pfalcato/Spartix/kernel"
.LASF8:
	.string	"unsigned int"
.LASF7:
	.string	"long long unsigned int"
.LASF12:
	.string	"arch/i386/syscall.cpp"
.LASF10:
	.string	"sizetype"
.LASF3:
	.string	"long long int"
.LASF1:
	.string	"short int"
.LASF14:
	.string	"uint32_t"
.LASF2:
	.string	"long int"
.LASF9:
	.string	"long double"
.LASF0:
	.string	"signed char"
	.ident	"GCC: (GNU) 5.3.0"
