	.file	"pit.cpp"
	.text
.Ltext0:
	.section	.rodata.str1.1,"aMS",@progbits,1
.LC0:
	.string	"EIP:0x%x\n"
.LC1:
	.string	"Preempting"
	.section	.text.unlikely,"ax",@progbits
.LCOLDB2:
	.text
.LHOTB2:
	.align 16
	.section	.text.unlikely
.Ltext_cold0:
	.text
	.globl	_Z13timer_handlerj
	.type	_Z13timer_handlerj, @function
_Z13timer_handlerj:
.LFB7:
	.file 1 "arch/i386/pit.cpp"
	.loc 1 38 0
	.cfi_startproc
.LVL0:
	pushl	%edi
	.cfi_def_cfa_offset 8
	.cfi_offset 7, -8
	pushl	%esi
	.cfi_def_cfa_offset 12
	.cfi_offset 6, -12
	pushl	%ebx
	.cfi_def_cfa_offset 16
	.cfi_offset 3, -16
	.loc 1 40 0
	movl	_ZL19scheduler_last_time+4, %ebx
	movl	_ZL19scheduler_last_time, %ecx
	.loc 1 41 0
	movl	_ZL11timer_ticks+4, %edx
	.loc 1 40 0
	movl	%ebx, %eax
	orl	%ecx, %eax
	.loc 1 41 0
	movl	_ZL11timer_ticks, %eax
	.loc 1 40 0
	jne	.L3
	.loc 1 41 0
	movl	%eax, _ZL19scheduler_last_time
	movl	%edx, _ZL19scheduler_last_time+4
	movl	%eax, %ecx
	movl	%edx, %ebx
.L3:
	.loc 1 42 0
	movl	%eax, %esi
	movl	%edx, %edi
	addl	$-2, %esi
	adcl	$-1, %edi
	xorl	%esi, %ecx
	xorl	%edi, %ebx
	orl	%ecx, %ebx
	je	.L7
.L4:
	.loc 1 48 0
	addl	$1, %eax
	adcl	$0, %edx
	movl	%eax, _ZL11timer_ticks
	.loc 1 49 0
	popl	%ebx
	.cfi_remember_state
	.cfi_restore 3
	.cfi_def_cfa_offset 12
	.loc 1 48 0
	movl	%edx, _ZL11timer_ticks+4
	.loc 1 49 0
	popl	%esi
	.cfi_restore 6
	.cfi_def_cfa_offset 8
	popl	%edi
	.cfi_restore 7
	.cfi_def_cfa_offset 4
	ret
	.align 16
.L7:
	.cfi_restore_state
	.loc 1 43 0
	subl	$8, %esp
	.cfi_def_cfa_offset 24
	pushl	24(%esp)
	.cfi_def_cfa_offset 28
	pushl	$.LC0
	.cfi_def_cfa_offset 32
	call	printf
.LVL1:
	.loc 1 44 0
	movl	$.LC1, (%esp)
	call	puts
.LVL2:
	.loc 1 45 0
	popl	%eax
	.cfi_def_cfa_offset 28
	pushl	28(%esp)
	.cfi_def_cfa_offset 32
	call	_Z7preemptm
.LVL3:
	.loc 1 46 0
	movl	_ZL11timer_ticks, %eax
	movl	_ZL11timer_ticks+4, %edx
	addl	$16, %esp
	.cfi_def_cfa_offset 16
	movl	%eax, _ZL19scheduler_last_time
	movl	%edx, _ZL19scheduler_last_time+4
	jmp	.L4
	.cfi_endproc
.LFE7:
	.size	_Z13timer_handlerj, .-_Z13timer_handlerj
	.section	.text.unlikely
.LCOLDE2:
	.text
.LHOTE2:
	.section	.text.unlikely
.LCOLDB3:
	.text
.LHOTB3:
	.align 16
	.globl	_ZN3PIT4InitEm
	.type	_ZN3PIT4InitEm, @function
_ZN3PIT4InitEm:
.LFB8:
	.loc 1 53 0
	.cfi_startproc
.LVL4:
	subl	$24, %esp
	.cfi_def_cfa_offset 28
	.loc 1 54 0
	xorl	%edx, %edx
	movl	$1193180, %eax
	divl	28(%esp)
	movl	%eax, %ecx
.LVL5:
.LBB14:
.LBB15:
	.file 2 "include/kernel/portio.h"
	.loc 2 22 0
	movl	$54, %eax
.LVL6:
/APP
/  22 "include/kernel/portio.h" 1
	outb %al, $67
/  0 "" 2
.LVL7:
/NO_APP
.LBE15:
.LBE14:
.LBB16:
.LBB17:
	.loc 2 54 0
	xorl	%eax, %eax
/APP
/  54 "include/kernel/portio.h" 1
	outb %al, $0x80
/  0 "" 2
.LVL8:
/NO_APP
.LBE17:
.LBE16:
.LBB18:
.LBB19:
	.loc 2 22 0
	movl	%ecx, %eax
/APP
/  22 "include/kernel/portio.h" 1
	outb %al, $64
/  0 "" 2
.LVL9:
/NO_APP
.LBE19:
.LBE18:
.LBB20:
.LBB21:
	.loc 2 54 0
	xorl	%eax, %eax
/APP
/  54 "include/kernel/portio.h" 1
	outb %al, $0x80
/  0 "" 2
.LVL10:
/NO_APP
.LBE21:
.LBE20:
.LBB22:
.LBB23:
	.loc 2 22 0
	movl	%ecx, %eax
	sarl	$8, %eax
/APP
/  22 "include/kernel/portio.h" 1
	outb %al, $64
/  0 "" 2
.LVL11:
/NO_APP
.LBE23:
.LBE22:
.LBB24:
.LBB25:
	.loc 2 54 0
	xorl	%eax, %eax
/APP
/  54 "include/kernel/portio.h" 1
	outb %al, $0x80
/  0 "" 2
/NO_APP
.LBE25:
.LBE24:
	.loc 1 62 0
	pushl	$0
	.cfi_def_cfa_offset 32
	call	_ZN3PIC9UnmaskIRQEt
.LVL12:
	.loc 1 66 0
	popl	%eax
	.cfi_def_cfa_offset 28
	popl	%edx
	.cfi_def_cfa_offset 24
	pushl	$_Z13timer_handlerj
	.cfi_def_cfa_offset 28
	pushl	$0
	.cfi_def_cfa_offset 32
	call	_ZN3IRQ14InstallHandlerEiPFvjE
.LVL13:
	.loc 1 67 0
	addl	$28, %esp
	.cfi_def_cfa_offset 4
	ret
	.cfi_endproc
.LFE8:
	.size	_ZN3PIT4InitEm, .-_ZN3PIT4InitEm
	.section	.text.unlikely
.LCOLDE3:
	.text
.LHOTE3:
	.section	.text.unlikely
.LCOLDB4:
	.text
.LHOTB4:
	.align 16
	.globl	_ZN3PIT12GetTickCountEv
	.type	_ZN3PIT12GetTickCountEv, @function
_ZN3PIT12GetTickCountEv:
.LFB9:
	.loc 1 70 0
	.cfi_startproc
	.loc 1 72 0
	movl	_ZL11timer_ticks, %eax
	movl	_ZL11timer_ticks+4, %edx
	ret
	.cfi_endproc
.LFE9:
	.size	_ZN3PIT12GetTickCountEv, .-_ZN3PIT12GetTickCountEv
	.section	.text.unlikely
.LCOLDE4:
	.text
.LHOTE4:
	.local	_ZL19scheduler_last_time
	.comm	_ZL19scheduler_last_time,8,8
	.local	_ZL11timer_ticks
	.comm	_ZL11timer_ticks,8,8
.Letext0:
	.section	.text.unlikely
.Letext_cold0:
	.file 3 "include/kernel/irq.h"
	.file 4 "/home/pfalcato/i686-elf/lib/gcc/i686-elf/5.3.0/include/stdint-gcc.h"
	.file 5 "include/kernel/pit.h"
	.file 6 "/home/pfalcato/Spartix/sysroot/usr/include/stdio.h"
	.file 7 "include/kernel/task_scheduler.h"
	.section	.debug_info,"",@progbits
.Ldebug_info0:
	.long	0x292
	.value	0x4
	.long	.Ldebug_abbrev0
	.byte	0x4
	.uleb128 0x1
	.long	.LASF20
	.byte	0x4
	.long	.LASF21
	.long	.LASF22
	.long	.Ltext0
	.long	.Letext0-.Ltext0
	.long	.Ldebug_line0
	.uleb128 0x2
	.byte	0x4
	.byte	0x7
	.long	.LASF0
	.uleb128 0x3
	.long	.LASF5
	.byte	0x3
	.byte	0x11
	.long	0x37
	.uleb128 0x4
	.byte	0x4
	.long	0x3d
	.uleb128 0x5
	.long	0x48
	.uleb128 0x6
	.long	0x25
	.byte	0
	.uleb128 0x7
	.byte	0x4
	.byte	0x5
	.string	"int"
	.uleb128 0x2
	.byte	0x1
	.byte	0x6
	.long	.LASF1
	.uleb128 0x2
	.byte	0x2
	.byte	0x5
	.long	.LASF2
	.uleb128 0x2
	.byte	0x4
	.byte	0x5
	.long	.LASF3
	.uleb128 0x2
	.byte	0x8
	.byte	0x5
	.long	.LASF4
	.uleb128 0x3
	.long	.LASF6
	.byte	0x4
	.byte	0x2e
	.long	0x76
	.uleb128 0x2
	.byte	0x1
	.byte	0x8
	.long	.LASF7
	.uleb128 0x3
	.long	.LASF8
	.byte	0x4
	.byte	0x31
	.long	0x88
	.uleb128 0x2
	.byte	0x2
	.byte	0x7
	.long	.LASF9
	.uleb128 0x3
	.long	.LASF10
	.byte	0x4
	.byte	0x34
	.long	0x9a
	.uleb128 0x2
	.byte	0x4
	.byte	0x7
	.long	.LASF11
	.uleb128 0x3
	.long	.LASF12
	.byte	0x4
	.byte	0x37
	.long	0xac
	.uleb128 0x2
	.byte	0x8
	.byte	0x7
	.long	.LASF13
	.uleb128 0x8
	.long	.LASF23
	.byte	0x2
	.byte	0x32
	.byte	0x3
	.uleb128 0x9
	.long	.LASF24
	.byte	0x2
	.byte	0x14
	.byte	0x3
	.long	0xde
	.uleb128 0xa
	.long	.LASF14
	.byte	0x2
	.byte	0x14
	.long	0x7d
	.uleb128 0xb
	.string	"val"
	.byte	0x2
	.byte	0x14
	.long	0x6b
	.byte	0
	.uleb128 0xc
	.long	.LASF25
	.byte	0x1
	.byte	0x25
	.long	.LASF26
	.long	.LFB7
	.long	.LFE7-.LFB7
	.uleb128 0x1
	.byte	0x9c
	.long	0x121
	.uleb128 0xd
	.string	"eip"
	.byte	0x1
	.byte	0x25
	.long	0x25
	.uleb128 0x2
	.byte	0x91
	.sleb128 0
	.uleb128 0xe
	.long	.LVL1
	.long	0x26e
	.uleb128 0xe
	.long	.LVL2
	.long	0x279
	.uleb128 0xe
	.long	.LVL3
	.long	0x286
	.byte	0
	.uleb128 0xf
	.string	"PIT"
	.byte	0x5
	.byte	0x13
	.long	0x151
	.uleb128 0x10
	.long	.LASF27
	.byte	0x1
	.byte	0x34
	.long	.LASF28
	.long	0x141
	.uleb128 0x6
	.long	0x8f
	.byte	0
	.uleb128 0x11
	.long	.LASF29
	.byte	0x1
	.byte	0x45
	.long	.LASF30
	.long	0xa1
	.byte	0
	.uleb128 0x12
	.long	0x12c
	.long	.LFB8
	.long	.LFE8-.LFB8
	.uleb128 0x1
	.byte	0x9c
	.long	0x23d
	.uleb128 0x13
	.long	.LASF15
	.byte	0x1
	.byte	0x34
	.long	0x8f
	.uleb128 0x2
	.byte	0x91
	.sleb128 0
	.uleb128 0x14
	.long	.LASF16
	.byte	0x1
	.byte	0x36
	.long	0x48
	.long	.LLST0
	.uleb128 0x15
	.long	.LASF17
	.byte	0x1
	.byte	0x40
	.long	0x2c
	.uleb128 0x6
	.byte	0x3
	.long	_Z13timer_handlerj
	.byte	0x9f
	.uleb128 0x16
	.long	0xbb
	.long	.LBB14
	.long	.LBE14-.LBB14
	.byte	0x1
	.byte	0x38
	.long	0x1b9
	.uleb128 0x17
	.long	0xd2
	.long	.LLST1
	.uleb128 0x17
	.long	0xc7
	.long	.LLST2
	.byte	0
	.uleb128 0x18
	.long	0xb3
	.long	.LBB16
	.long	.LBE16-.LBB16
	.byte	0x1
	.byte	0x39
	.uleb128 0x16
	.long	0xbb
	.long	.LBB18
	.long	.LBE18-.LBB18
	.byte	0x1
	.byte	0x3a
	.long	0x1ee
	.uleb128 0x17
	.long	0xd2
	.long	.LLST3
	.uleb128 0x17
	.long	0xc7
	.long	.LLST4
	.byte	0
	.uleb128 0x18
	.long	0xb3
	.long	.LBB20
	.long	.LBE20-.LBB20
	.byte	0x1
	.byte	0x3b
	.uleb128 0x16
	.long	0xbb
	.long	.LBB22
	.long	.LBE22-.LBB22
	.byte	0x1
	.byte	0x3c
	.long	0x223
	.uleb128 0x17
	.long	0xd2
	.long	.LLST5
	.uleb128 0x17
	.long	0xc7
	.long	.LLST6
	.byte	0
	.uleb128 0x18
	.long	0xb3
	.long	.LBB24
	.long	.LBE24-.LBB24
	.byte	0x1
	.byte	0x3d
	.uleb128 0x19
	.long	.LVL12
	.uleb128 0x19
	.long	.LVL13
	.byte	0
	.uleb128 0x1a
	.long	0x141
	.long	.LFB9
	.long	.LFE9-.LFB9
	.uleb128 0x1
	.byte	0x9c
	.uleb128 0x15
	.long	.LASF18
	.byte	0x1
	.byte	0x22
	.long	0xa1
	.uleb128 0x5
	.byte	0x3
	.long	_ZL11timer_ticks
	.uleb128 0x15
	.long	.LASF19
	.byte	0x1
	.byte	0x24
	.long	0xa1
	.uleb128 0x5
	.byte	0x3
	.long	_ZL19scheduler_last_time
	.uleb128 0x1b
	.long	.LASF31
	.long	.LASF31
	.byte	0x6
	.byte	0x18
	.uleb128 0x1c
	.long	.LASF32
	.long	.LASF33
	.long	.LASF32
	.uleb128 0x1d
	.long	.LASF34
	.long	.LASF35
	.byte	0x7
	.byte	0x1c
	.long	.LASF34
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
	.uleb128 0xf
	.byte	0
	.uleb128 0xb
	.uleb128 0xb
	.uleb128 0x49
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0x5
	.uleb128 0x15
	.byte	0x1
	.uleb128 0x1
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0x6
	.uleb128 0x5
	.byte	0
	.uleb128 0x49
	.uleb128 0x13
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
	.byte	0
	.uleb128 0x3
	.uleb128 0xe
	.uleb128 0x3a
	.uleb128 0xb
	.uleb128 0x3b
	.uleb128 0xb
	.uleb128 0x20
	.uleb128 0xb
	.byte	0
	.byte	0
	.uleb128 0x9
	.uleb128 0x2e
	.byte	0x1
	.uleb128 0x3
	.uleb128 0xe
	.uleb128 0x3a
	.uleb128 0xb
	.uleb128 0x3b
	.uleb128 0xb
	.uleb128 0x20
	.uleb128 0xb
	.uleb128 0x1
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0xa
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
	.uleb128 0xb
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
	.uleb128 0xc
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
	.uleb128 0xd
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
	.uleb128 0xe
	.uleb128 0x4109
	.byte	0
	.uleb128 0x11
	.uleb128 0x1
	.uleb128 0x31
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0xf
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
	.uleb128 0x10
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
	.uleb128 0x11
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
	.uleb128 0x49
	.uleb128 0x13
	.uleb128 0x3c
	.uleb128 0x19
	.byte	0
	.byte	0
	.uleb128 0x12
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
	.uleb128 0x13
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
	.uleb128 0x14
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
	.uleb128 0x17
	.uleb128 0x5
	.byte	0
	.uleb128 0x31
	.uleb128 0x13
	.uleb128 0x2
	.uleb128 0x17
	.byte	0
	.byte	0
	.uleb128 0x18
	.uleb128 0x1d
	.byte	0
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
	.byte	0
	.byte	0
	.uleb128 0x19
	.uleb128 0x4109
	.byte	0
	.uleb128 0x11
	.uleb128 0x1
	.byte	0
	.byte	0
	.uleb128 0x1a
	.uleb128 0x2e
	.byte	0
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
	.byte	0
	.byte	0
	.uleb128 0x1b
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
	.uleb128 0x1c
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
	.uleb128 0x1d
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
	.long	.LVL5-.Ltext0
	.long	.LVL6-.Ltext0
	.value	0x1
	.byte	0x50
	.long	.LVL6-.Ltext0
	.long	.LVL12-1-.Ltext0
	.value	0x1
	.byte	0x51
	.long	.LVL12-1-.Ltext0
	.long	.LFE8-.Ltext0
	.value	0x10
	.byte	0xc
	.long	0x1234dc
	.byte	0xf7
	.uleb128 0x25
	.byte	0x91
	.sleb128 0
	.byte	0x6
	.byte	0xf7
	.uleb128 0x25
	.byte	0x1b
	.byte	0xf7
	.uleb128 0
	.byte	0x9f
	.long	0
	.long	0
.LLST1:
	.long	.LVL5-.Ltext0
	.long	.LVL7-.Ltext0
	.value	0x3
	.byte	0x8
	.byte	0x36
	.byte	0x9f
	.long	0
	.long	0
.LLST2:
	.long	.LVL5-.Ltext0
	.long	.LVL7-.Ltext0
	.value	0x3
	.byte	0x8
	.byte	0x43
	.byte	0x9f
	.long	0
	.long	0
.LLST3:
	.long	.LVL8-.Ltext0
	.long	.LVL9-.Ltext0
	.value	0x1
	.byte	0x51
	.long	0
	.long	0
.LLST4:
	.long	.LVL8-.Ltext0
	.long	.LVL9-.Ltext0
	.value	0x3
	.byte	0x8
	.byte	0x40
	.byte	0x9f
	.long	0
	.long	0
.LLST5:
	.long	.LVL10-.Ltext0
	.long	.LVL11-.Ltext0
	.value	0x5
	.byte	0x71
	.sleb128 0
	.byte	0x38
	.byte	0x26
	.byte	0x9f
	.long	0
	.long	0
.LLST6:
	.long	.LVL10-.Ltext0
	.long	.LVL11-.Ltext0
	.value	0x3
	.byte	0x8
	.byte	0x40
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
	.section	.debug_line,"",@progbits
.Ldebug_line0:
	.section	.debug_str,"MS",@progbits,1
.LASF35:
	.string	"preempt"
.LASF29:
	.string	"GetTickCount"
.LASF16:
	.string	"divisor"
.LASF12:
	.string	"uint64_t"
.LASF31:
	.string	"printf"
.LASF20:
	.string	"GNU C++11 5.3.0 -mtune=generic -march=pentiumpro -g -O2 -std=c++11 -ffreestanding -fbuiltin -fstack-protector-strong -fno-exceptions -fno-rtti"
.LASF1:
	.string	"signed char"
.LASF7:
	.string	"unsigned char"
.LASF34:
	.string	"_Z7preemptm"
.LASF11:
	.string	"long unsigned int"
.LASF9:
	.string	"short unsigned int"
.LASF27:
	.string	"Init"
.LASF18:
	.string	"timer_ticks"
.LASF21:
	.string	"arch/i386/pit.cpp"
.LASF26:
	.string	"_Z13timer_handlerj"
.LASF22:
	.string	"/home/pfalcato/Spartix/kernel"
.LASF28:
	.string	"_ZN3PIT4InitEm"
.LASF24:
	.string	"outb"
.LASF19:
	.string	"scheduler_last_time"
.LASF0:
	.string	"unsigned int"
.LASF13:
	.string	"long long unsigned int"
.LASF6:
	.string	"uint8_t"
.LASF15:
	.string	"frequency"
.LASF30:
	.string	"_ZN3PIT12GetTickCountEv"
.LASF17:
	.string	"handler"
.LASF4:
	.string	"long long int"
.LASF14:
	.string	"port"
.LASF2:
	.string	"short int"
.LASF8:
	.string	"uint16_t"
.LASF10:
	.string	"uint32_t"
.LASF3:
	.string	"long int"
.LASF25:
	.string	"timer_handler"
.LASF32:
	.string	"puts"
.LASF5:
	.string	"irq_t"
.LASF23:
	.string	"io_wait"
.LASF33:
	.string	"__builtin_puts"
	.ident	"GCC: (GNU) 5.3.0"
