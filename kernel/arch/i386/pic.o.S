	.file	"pic.cpp"
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
	.globl	_ZN3PIC7DisableEv
	.type	_ZN3PIC7DisableEv, @function
_ZN3PIC7DisableEv:
.LFB8:
	.file 1 "arch/i386/pic.cpp"
	.loc 1 41 0
	.cfi_startproc
.LVL0:
.LBB84:
.LBB85:
	.file 2 "include/kernel/portio.h"
	.loc 2 22 0
	movl	$-1, %eax
/APP
/  22 "include/kernel/portio.h" 1
	outb %al, $161
/  0 "" 2
.LVL1:
/NO_APP
.LBE85:
.LBE84:
.LBB86:
.LBB87:
/APP
/  22 "include/kernel/portio.h" 1
	outb %al, $33
/  0 "" 2
.LVL2:
/NO_APP
	ret
.LBE87:
.LBE86:
	.cfi_endproc
.LFE8:
	.size	_ZN3PIC7DisableEv, .-_ZN3PIC7DisableEv
	.section	.text.unlikely
.LCOLDE0:
	.text
.LHOTE0:
	.section	.text.unlikely
.LCOLDB1:
	.text
.LHOTB1:
	.align 16
	.globl	_ZN3PIC5RemapEv
	.type	_ZN3PIC5RemapEv, @function
_ZN3PIC5RemapEv:
.LFB9:
	.loc 1 47 0
	.cfi_startproc
.LVL3:
.LBB88:
.LBB89:
	.loc 2 22 0
	movl	$17, %eax
/APP
/  22 "include/kernel/portio.h" 1
	outb %al, $32
/  0 "" 2
.LVL4:
/NO_APP
.LBE89:
.LBE88:
.LBB90:
.LBB91:
	.loc 2 54 0
	xorl	%eax, %eax
/APP
/  54 "include/kernel/portio.h" 1
	outb %al, $0x80
/  0 "" 2
.LVL5:
/NO_APP
.LBE91:
.LBE90:
.LBB92:
.LBB93:
	.loc 2 22 0
	movl	$17, %eax
/APP
/  22 "include/kernel/portio.h" 1
	outb %al, $160
/  0 "" 2
.LVL6:
/NO_APP
.LBE93:
.LBE92:
.LBB94:
.LBB95:
	.loc 2 54 0
	xorl	%eax, %eax
/APP
/  54 "include/kernel/portio.h" 1
	outb %al, $0x80
/  0 "" 2
.LVL7:
/NO_APP
.LBE95:
.LBE94:
.LBB96:
.LBB97:
	.loc 2 22 0
	movl	$32, %eax
/APP
/  22 "include/kernel/portio.h" 1
	outb %al, $33
/  0 "" 2
.LVL8:
/NO_APP
.LBE97:
.LBE96:
.LBB98:
.LBB99:
	.loc 2 54 0
	xorl	%eax, %eax
/APP
/  54 "include/kernel/portio.h" 1
	outb %al, $0x80
/  0 "" 2
.LVL9:
/NO_APP
.LBE99:
.LBE98:
.LBB100:
.LBB101:
	.loc 2 22 0
	movl	$40, %eax
/APP
/  22 "include/kernel/portio.h" 1
	outb %al, $161
/  0 "" 2
.LVL10:
/NO_APP
.LBE101:
.LBE100:
.LBB102:
.LBB103:
	.loc 2 54 0
	xorl	%eax, %eax
/APP
/  54 "include/kernel/portio.h" 1
	outb %al, $0x80
/  0 "" 2
.LVL11:
/NO_APP
.LBE103:
.LBE102:
.LBB104:
.LBB105:
	.loc 2 22 0
	movl	$4, %eax
/APP
/  22 "include/kernel/portio.h" 1
	outb %al, $33
/  0 "" 2
.LVL12:
/NO_APP
.LBE105:
.LBE104:
.LBB106:
.LBB107:
	.loc 2 54 0
	xorl	%eax, %eax
/APP
/  54 "include/kernel/portio.h" 1
	outb %al, $0x80
/  0 "" 2
.LVL13:
/NO_APP
.LBE107:
.LBE106:
.LBB108:
.LBB109:
	.loc 2 22 0
	movl	$2, %eax
/APP
/  22 "include/kernel/portio.h" 1
	outb %al, $161
/  0 "" 2
.LVL14:
/NO_APP
.LBE109:
.LBE108:
.LBB110:
.LBB111:
	.loc 2 54 0
	xorl	%eax, %eax
/APP
/  54 "include/kernel/portio.h" 1
	outb %al, $0x80
/  0 "" 2
.LVL15:
/NO_APP
.LBE111:
.LBE110:
.LBB112:
.LBB113:
	.loc 2 22 0
	movl	$1, %eax
/APP
/  22 "include/kernel/portio.h" 1
	outb %al, $33
/  0 "" 2
.LVL16:
/NO_APP
.LBE113:
.LBE112:
.LBB114:
.LBB115:
	.loc 2 54 0
	xorl	%eax, %eax
/APP
/  54 "include/kernel/portio.h" 1
	outb %al, $0x80
/  0 "" 2
.LVL17:
/NO_APP
.LBE115:
.LBE114:
.LBB116:
.LBB117:
	.loc 2 22 0
	movl	$1, %eax
/APP
/  22 "include/kernel/portio.h" 1
	outb %al, $161
/  0 "" 2
.LVL18:
/NO_APP
.LBE117:
.LBE116:
.LBB118:
.LBB119:
	.loc 2 54 0
	xorl	%eax, %eax
/APP
/  54 "include/kernel/portio.h" 1
	outb %al, $0x80
/  0 "" 2
.LVL19:
/NO_APP
.LBE119:
.LBE118:
.LBB120:
.LBB121:
	.loc 2 22 0
/APP
/  22 "include/kernel/portio.h" 1
	outb %al, $33
/  0 "" 2
.LVL20:
/NO_APP
.LBE121:
.LBE120:
.LBB122:
.LBB123:
	.loc 2 54 0
	xorl	%eax, %eax
/APP
/  54 "include/kernel/portio.h" 1
	outb %al, $0x80
/  0 "" 2
.LVL21:
/NO_APP
.LBE123:
.LBE122:
.LBB124:
.LBB125:
	.loc 2 22 0
/APP
/  22 "include/kernel/portio.h" 1
	outb %al, $161
/  0 "" 2
.LVL22:
/NO_APP
	ret
.LBE125:
.LBE124:
	.cfi_endproc
.LFE9:
	.size	_ZN3PIC5RemapEv, .-_ZN3PIC5RemapEv
	.section	.text.unlikely
.LCOLDE1:
	.text
.LHOTE1:
	.section	.text.unlikely
.LCOLDB2:
	.text
.LHOTB2:
	.align 16
	.globl	_ZN3PIC9UnmaskIRQEt
	.type	_ZN3PIC9UnmaskIRQEt, @function
_ZN3PIC9UnmaskIRQEt:
.LFB10:
	.loc 1 70 0
	.cfi_startproc
.LVL23:
	pushl	%ebx
	.cfi_def_cfa_offset 8
	.cfi_offset 3, -8
	.loc 1 70 0
	movl	8(%esp), %eax
	.loc 1 74 0
	cmpw	$7, %ax
	jbe	.L6
.LVL24:
	.loc 1 78 0
	leal	-8(%eax), %ecx
.LVL25:
	.loc 1 77 0
	movl	$161, %edx
.LVL26:
.L4:
.LBB126:
.LBB127:
	.loc 2 35 0
/APP
/  35 "include/kernel/portio.h" 1
	inb %dx, %al
/  0 "" 2
.LVL27:
/NO_APP
.LBE127:
.LBE126:
.LBB128:
.LBB129:
	.loc 2 22 0
	movl	$-2, %ebx
	roll	%cl, %ebx
	andl	%ebx, %eax
.LVL28:
/APP
/  22 "include/kernel/portio.h" 1
	outb %al, %dx
/  0 "" 2
.LVL29:
/NO_APP
.LBE129:
.LBE128:
	.loc 1 82 0
	popl	%ebx
	.cfi_remember_state
	.cfi_restore 3
	.cfi_def_cfa_offset 4
	ret
.LVL30:
	.align 16
.L6:
	.cfi_restore_state
	movl	%eax, %ecx
	movl	$33, %edx
	jmp	.L4
	.cfi_endproc
.LFE10:
	.size	_ZN3PIC9UnmaskIRQEt, .-_ZN3PIC9UnmaskIRQEt
	.section	.text.unlikely
.LCOLDE2:
	.text
.LHOTE2:
	.section	.text.unlikely
.LCOLDB3:
	.text
.LHOTB3:
	.align 16
	.globl	_ZN3PIC7MaskIRQEt
	.type	_ZN3PIC7MaskIRQEt, @function
_ZN3PIC7MaskIRQEt:
.LFB11:
	.loc 1 85 0
	.cfi_startproc
.LVL31:
	pushl	%ebx
	.cfi_def_cfa_offset 8
	.cfi_offset 3, -8
	.loc 1 85 0
	movl	8(%esp), %eax
	.loc 1 88 0
	cmpw	$7, %ax
	jbe	.L12
.LVL32:
	.loc 1 92 0
	leal	-8(%eax), %ecx
.LVL33:
	.loc 1 91 0
	movl	$161, %edx
.LVL34:
.L10:
.LBB130:
.LBB131:
	.loc 2 35 0
/APP
/  35 "include/kernel/portio.h" 1
	inb %dx, %al
/  0 "" 2
.LVL35:
/NO_APP
.LBE131:
.LBE130:
.LBB132:
.LBB133:
	.loc 2 22 0
	movl	$1, %ebx
	sall	%cl, %ebx
	orl	%ebx, %eax
.LVL36:
/APP
/  22 "include/kernel/portio.h" 1
	outb %al, %dx
/  0 "" 2
.LVL37:
/NO_APP
.LBE133:
.LBE132:
	.loc 1 96 0
	popl	%ebx
	.cfi_remember_state
	.cfi_restore 3
	.cfi_def_cfa_offset 4
	ret
.LVL38:
	.align 16
.L12:
	.cfi_restore_state
	movl	%eax, %ecx
	movl	$33, %edx
	jmp	.L10
	.cfi_endproc
.LFE11:
	.size	_ZN3PIC7MaskIRQEt, .-_ZN3PIC7MaskIRQEt
	.section	.text.unlikely
.LCOLDE3:
	.text
.LHOTE3:
	.section	.text.unlikely
.LCOLDB4:
	.text
.LHOTB4:
	.align 16
	.globl	_ZN3PIC6GetIRREv
	.type	_ZN3PIC6GetIRREv, @function
_ZN3PIC6GetIRREv:
.LFB12:
	.loc 1 100 0
	.cfi_startproc
.LVL39:
.LBB134:
.LBB135:
.LBB136:
.LBB137:
	.loc 2 22 0
	movl	$10, %eax
/APP
/  22 "include/kernel/portio.h" 1
	outb %al, $32
/  0 "" 2
.LVL40:
/NO_APP
.LBE137:
.LBE136:
.LBB138:
.LBB139:
/APP
/  22 "include/kernel/portio.h" 1
	outb %al, $160
/  0 "" 2
.LVL41:
/NO_APP
.LBE139:
.LBE138:
.LBB140:
.LBB141:
	.loc 2 35 0
/APP
/  35 "include/kernel/portio.h" 1
	inb $160, %al
/  0 "" 2
/NO_APP
	movl	%eax, %ecx
.LVL42:
.LBE141:
.LBE140:
.LBB142:
.LBB143:
/APP
/  35 "include/kernel/portio.h" 1
	inb $32, %al
/  0 "" 2
/NO_APP
	movzbl	%al, %edx
.LVL43:
.LBE143:
.LBE142:
.LBE135:
.LBE134:
	.loc 1 101 0
	movl	%ecx, %eax
	sall	$8, %eax
	orl	%edx, %eax
	.loc 1 102 0
	ret
	.cfi_endproc
.LFE12:
	.size	_ZN3PIC6GetIRREv, .-_ZN3PIC6GetIRREv
	.section	.text.unlikely
.LCOLDE4:
	.text
.LHOTE4:
	.section	.text.unlikely
.LCOLDB5:
	.text
.LHOTB5:
	.align 16
	.globl	_ZN3PIC7SendEOIEh
	.type	_ZN3PIC7SendEOIEh, @function
_ZN3PIC7SendEOIEh:
.LFB13:
	.loc 1 104 0
	.cfi_startproc
.LVL44:
	.loc 1 105 0
	cmpb	$7, 4(%esp)
	jbe	.L16
.LVL45:
.LBB144:
.LBB145:
	.loc 2 22 0
	movl	$32, %eax
/APP
/  22 "include/kernel/portio.h" 1
	outb %al, $160
/  0 "" 2
.LVL46:
/NO_APP
.L16:
.LBE145:
.LBE144:
.LBB146:
.LBB147:
	movl	$32, %eax
/APP
/  22 "include/kernel/portio.h" 1
	outb %al, $32
/  0 "" 2
.LVL47:
/NO_APP
	ret
.LBE147:
.LBE146:
	.cfi_endproc
.LFE13:
	.size	_ZN3PIC7SendEOIEh, .-_ZN3PIC7SendEOIEh
	.section	.text.unlikely
.LCOLDE5:
	.text
.LHOTE5:
	.section	.text.unlikely
.LCOLDB6:
	.text
.LHOTB6:
	.align 16
	.globl	_ZN3PIC6GetISREv
	.type	_ZN3PIC6GetISREv, @function
_ZN3PIC6GetISREv:
.LFB14:
	.loc 1 112 0
	.cfi_startproc
.LVL48:
.LBB148:
.LBB149:
.LBB150:
.LBB151:
	.loc 2 22 0
	movl	$11, %eax
/APP
/  22 "include/kernel/portio.h" 1
	outb %al, $32
/  0 "" 2
.LVL49:
/NO_APP
.LBE151:
.LBE150:
.LBB152:
.LBB153:
/APP
/  22 "include/kernel/portio.h" 1
	outb %al, $160
/  0 "" 2
.LVL50:
/NO_APP
.LBE153:
.LBE152:
.LBB154:
.LBB155:
	.loc 2 35 0
/APP
/  35 "include/kernel/portio.h" 1
	inb $160, %al
/  0 "" 2
/NO_APP
	movl	%eax, %ecx
.LVL51:
.LBE155:
.LBE154:
.LBB156:
.LBB157:
/APP
/  35 "include/kernel/portio.h" 1
	inb $32, %al
/  0 "" 2
/NO_APP
	movzbl	%al, %edx
.LVL52:
.LBE157:
.LBE156:
.LBE149:
.LBE148:
	.loc 1 113 0
	movl	%ecx, %eax
	sall	$8, %eax
	orl	%edx, %eax
	.loc 1 114 0
	ret
	.cfi_endproc
.LFE14:
	.size	_ZN3PIC6GetISREv, .-_ZN3PIC6GetISREv
	.section	.text.unlikely
.LCOLDE6:
	.text
.LHOTE6:
.Letext0:
	.section	.text.unlikely
.Letext_cold0:
	.file 3 "/home/pfalcato/i686-elf/lib/gcc/i686-elf/5.3.0/include/stdint-gcc.h"
	.file 4 "include/kernel/pic.h"
	.section	.debug_info,"",@progbits
.Ldebug_info0:
	.long	0x6f8
	.value	0x4
	.long	.Ldebug_abbrev0
	.byte	0x4
	.uleb128 0x1
	.long	.LASF30
	.byte	0x4
	.long	.LASF31
	.long	.LASF32
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
	.uleb128 0x3
	.long	.LASF5
	.byte	0x3
	.byte	0x2e
	.long	0x4c
	.uleb128 0x2
	.byte	0x1
	.byte	0x8
	.long	.LASF4
	.uleb128 0x3
	.long	.LASF6
	.byte	0x3
	.byte	0x31
	.long	0x5e
	.uleb128 0x2
	.byte	0x2
	.byte	0x7
	.long	.LASF7
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
	.string	"inb"
	.byte	0x2
	.byte	0x20
	.long	0x41
	.byte	0x3
	.long	0xa8
	.uleb128 0x6
	.long	.LASF11
	.byte	0x2
	.byte	0x20
	.long	0x53
	.uleb128 0x7
	.string	"ret"
	.byte	0x2
	.byte	0x22
	.long	0x41
	.byte	0
	.uleb128 0x8
	.long	.LASF33
	.byte	0x2
	.byte	0x14
	.byte	0x3
	.long	0xcb
	.uleb128 0x6
	.long	.LASF11
	.byte	0x2
	.byte	0x14
	.long	0x53
	.uleb128 0x9
	.string	"val"
	.byte	0x2
	.byte	0x14
	.long	0x41
	.byte	0
	.uleb128 0xa
	.long	.LASF34
	.byte	0x2
	.byte	0x32
	.byte	0x3
	.uleb128 0xb
	.long	.LASF12
	.byte	0x1
	.byte	0x1d
	.long	0x53
	.byte	0x1
	.long	0xef
	.uleb128 0x6
	.long	.LASF13
	.byte	0x1
	.byte	0x1d
	.long	0x73
	.byte	0
	.uleb128 0xc
	.string	"PIC"
	.byte	0x4
	.byte	0x1c
	.long	0x16e
	.uleb128 0xd
	.long	.LASF14
	.byte	0x1
	.byte	0x28
	.long	.LASF16
	.uleb128 0xd
	.long	.LASF15
	.byte	0x1
	.byte	0x2e
	.long	.LASF17
	.uleb128 0xe
	.long	.LASF18
	.byte	0x1
	.byte	0x45
	.long	.LASF20
	.long	0x125
	.uleb128 0xf
	.long	0x53
	.byte	0
	.uleb128 0xe
	.long	.LASF19
	.byte	0x1
	.byte	0x54
	.long	.LASF21
	.long	0x13a
	.uleb128 0xf
	.long	0x53
	.byte	0
	.uleb128 0x10
	.long	.LASF24
	.byte	0x1
	.byte	0x63
	.long	.LASF26
	.long	0x53
	.uleb128 0xe
	.long	.LASF22
	.byte	0x1
	.byte	0x67
	.long	.LASF23
	.long	0x15e
	.uleb128 0xf
	.long	0x4c
	.byte	0
	.uleb128 0x10
	.long	.LASF25
	.byte	0x1
	.byte	0x6f
	.long	.LASF27
	.long	0x53
	.byte	0
	.uleb128 0x11
	.long	0xfa
	.long	.LFB8
	.long	.LFE8-.LFB8
	.uleb128 0x1
	.byte	0x9c
	.long	0x1ca
	.uleb128 0x12
	.long	0xa8
	.long	.LBB84
	.long	.LBE84-.LBB84
	.byte	0x1
	.byte	0x2a
	.long	0x1a7
	.uleb128 0x13
	.long	0xbf
	.long	.LLST0
	.uleb128 0x13
	.long	0xb4
	.long	.LLST1
	.byte	0
	.uleb128 0x14
	.long	0xa8
	.long	.LBB86
	.long	.LBE86-.LBB86
	.byte	0x1
	.byte	0x2b
	.uleb128 0x13
	.long	0xbf
	.long	.LLST2
	.uleb128 0x13
	.long	0xb4
	.long	.LLST3
	.byte	0
	.byte	0
	.uleb128 0x11
	.long	0x105
	.long	.LFB9
	.long	.LFE9-.LFB9
	.uleb128 0x1
	.byte	0x9c
	.long	0x3dd
	.uleb128 0x12
	.long	0xa8
	.long	.LBB88
	.long	.LBE88-.LBB88
	.byte	0x1
	.byte	0x30
	.long	0x203
	.uleb128 0x13
	.long	0xbf
	.long	.LLST4
	.uleb128 0x13
	.long	0xb4
	.long	.LLST5
	.byte	0
	.uleb128 0x15
	.long	0xcb
	.long	.LBB90
	.long	.LBE90-.LBB90
	.byte	0x1
	.byte	0x31
	.uleb128 0x12
	.long	0xa8
	.long	.LBB92
	.long	.LBE92-.LBB92
	.byte	0x1
	.byte	0x32
	.long	0x238
	.uleb128 0x13
	.long	0xbf
	.long	.LLST6
	.uleb128 0x13
	.long	0xb4
	.long	.LLST7
	.byte	0
	.uleb128 0x15
	.long	0xcb
	.long	.LBB94
	.long	.LBE94-.LBB94
	.byte	0x1
	.byte	0x33
	.uleb128 0x12
	.long	0xa8
	.long	.LBB96
	.long	.LBE96-.LBB96
	.byte	0x1
	.byte	0x34
	.long	0x26d
	.uleb128 0x13
	.long	0xbf
	.long	.LLST8
	.uleb128 0x13
	.long	0xb4
	.long	.LLST9
	.byte	0
	.uleb128 0x15
	.long	0xcb
	.long	.LBB98
	.long	.LBE98-.LBB98
	.byte	0x1
	.byte	0x35
	.uleb128 0x12
	.long	0xa8
	.long	.LBB100
	.long	.LBE100-.LBB100
	.byte	0x1
	.byte	0x36
	.long	0x2a2
	.uleb128 0x13
	.long	0xbf
	.long	.LLST10
	.uleb128 0x13
	.long	0xb4
	.long	.LLST11
	.byte	0
	.uleb128 0x15
	.long	0xcb
	.long	.LBB102
	.long	.LBE102-.LBB102
	.byte	0x1
	.byte	0x37
	.uleb128 0x12
	.long	0xa8
	.long	.LBB104
	.long	.LBE104-.LBB104
	.byte	0x1
	.byte	0x38
	.long	0x2d7
	.uleb128 0x13
	.long	0xbf
	.long	.LLST12
	.uleb128 0x13
	.long	0xb4
	.long	.LLST13
	.byte	0
	.uleb128 0x15
	.long	0xcb
	.long	.LBB106
	.long	.LBE106-.LBB106
	.byte	0x1
	.byte	0x39
	.uleb128 0x12
	.long	0xa8
	.long	.LBB108
	.long	.LBE108-.LBB108
	.byte	0x1
	.byte	0x3a
	.long	0x30c
	.uleb128 0x13
	.long	0xbf
	.long	.LLST14
	.uleb128 0x13
	.long	0xb4
	.long	.LLST15
	.byte	0
	.uleb128 0x15
	.long	0xcb
	.long	.LBB110
	.long	.LBE110-.LBB110
	.byte	0x1
	.byte	0x3b
	.uleb128 0x12
	.long	0xa8
	.long	.LBB112
	.long	.LBE112-.LBB112
	.byte	0x1
	.byte	0x3c
	.long	0x341
	.uleb128 0x13
	.long	0xbf
	.long	.LLST16
	.uleb128 0x13
	.long	0xb4
	.long	.LLST17
	.byte	0
	.uleb128 0x15
	.long	0xcb
	.long	.LBB114
	.long	.LBE114-.LBB114
	.byte	0x1
	.byte	0x3d
	.uleb128 0x12
	.long	0xa8
	.long	.LBB116
	.long	.LBE116-.LBB116
	.byte	0x1
	.byte	0x3e
	.long	0x376
	.uleb128 0x13
	.long	0xbf
	.long	.LLST18
	.uleb128 0x13
	.long	0xb4
	.long	.LLST19
	.byte	0
	.uleb128 0x15
	.long	0xcb
	.long	.LBB118
	.long	.LBE118-.LBB118
	.byte	0x1
	.byte	0x3f
	.uleb128 0x12
	.long	0xa8
	.long	.LBB120
	.long	.LBE120-.LBB120
	.byte	0x1
	.byte	0x40
	.long	0x3ab
	.uleb128 0x13
	.long	0xbf
	.long	.LLST20
	.uleb128 0x13
	.long	0xb4
	.long	.LLST21
	.byte	0
	.uleb128 0x15
	.long	0xcb
	.long	.LBB122
	.long	.LBE122-.LBB122
	.byte	0x1
	.byte	0x41
	.uleb128 0x14
	.long	0xa8
	.long	.LBB124
	.long	.LBE124-.LBB124
	.byte	0x1
	.byte	0x42
	.uleb128 0x13
	.long	0xbf
	.long	.LLST22
	.uleb128 0x13
	.long	0xb4
	.long	.LLST23
	.byte	0
	.byte	0
	.uleb128 0x11
	.long	0x110
	.long	.LFB10
	.long	.LFE10-.LFB10
	.uleb128 0x1
	.byte	0x9c
	.long	0x46c
	.uleb128 0x16
	.long	.LASF29
	.byte	0x1
	.byte	0x45
	.long	0x53
	.long	.LLST24
	.uleb128 0x17
	.long	.LASF11
	.byte	0x1
	.byte	0x47
	.long	0x53
	.long	.LLST25
	.uleb128 0x17
	.long	.LASF28
	.byte	0x1
	.byte	0x48
	.long	0x41
	.long	.LLST26
	.uleb128 0x12
	.long	0x81
	.long	.LBB126
	.long	.LBE126-.LBB126
	.byte	0x1
	.byte	0x50
	.long	0x449
	.uleb128 0x13
	.long	0x91
	.long	.LLST27
	.uleb128 0x18
	.long	.LBB127
	.long	.LBE127-.LBB127
	.uleb128 0x19
	.long	0x9c
	.byte	0
	.byte	0
	.uleb128 0x14
	.long	0xa8
	.long	.LBB128
	.long	.LBE128-.LBB128
	.byte	0x1
	.byte	0x51
	.uleb128 0x13
	.long	0xbf
	.long	.LLST26
	.uleb128 0x13
	.long	0xb4
	.long	.LLST29
	.byte	0
	.byte	0
	.uleb128 0x11
	.long	0x125
	.long	.LFB11
	.long	.LFE11-.LFB11
	.uleb128 0x1
	.byte	0x9c
	.long	0x4fb
	.uleb128 0x16
	.long	.LASF29
	.byte	0x1
	.byte	0x54
	.long	0x53
	.long	.LLST30
	.uleb128 0x17
	.long	.LASF11
	.byte	0x1
	.byte	0x56
	.long	0x53
	.long	.LLST31
	.uleb128 0x17
	.long	.LASF28
	.byte	0x1
	.byte	0x57
	.long	0x41
	.long	.LLST32
	.uleb128 0x12
	.long	0x81
	.long	.LBB130
	.long	.LBE130-.LBB130
	.byte	0x1
	.byte	0x5e
	.long	0x4d8
	.uleb128 0x13
	.long	0x91
	.long	.LLST33
	.uleb128 0x18
	.long	.LBB131
	.long	.LBE131-.LBB131
	.uleb128 0x19
	.long	0x9c
	.byte	0
	.byte	0
	.uleb128 0x14
	.long	0xa8
	.long	.LBB132
	.long	.LBE132-.LBB132
	.byte	0x1
	.byte	0x5f
	.uleb128 0x13
	.long	0xbf
	.long	.LLST32
	.uleb128 0x13
	.long	0xb4
	.long	.LLST35
	.byte	0
	.byte	0
	.uleb128 0x11
	.long	0x13a
	.long	.LFB12
	.long	.LFE12-.LFB12
	.uleb128 0x1
	.byte	0x9c
	.long	0x5c8
	.uleb128 0x14
	.long	0xd3
	.long	.LBB134
	.long	.LBE134-.LBB134
	.byte	0x1
	.byte	0x65
	.uleb128 0x13
	.long	0xe3
	.long	.LLST36
	.uleb128 0x12
	.long	0xa8
	.long	.LBB136
	.long	.LBE136-.LBB136
	.byte	0x1
	.byte	0x21
	.long	0x54c
	.uleb128 0x13
	.long	0xbf
	.long	.LLST37
	.uleb128 0x13
	.long	0xb4
	.long	.LLST38
	.byte	0
	.uleb128 0x12
	.long	0xa8
	.long	.LBB138
	.long	.LBE138-.LBB138
	.byte	0x1
	.byte	0x22
	.long	0x572
	.uleb128 0x13
	.long	0xbf
	.long	.LLST39
	.uleb128 0x13
	.long	0xb4
	.long	.LLST40
	.byte	0
	.uleb128 0x12
	.long	0x81
	.long	.LBB140
	.long	.LBE140-.LBB140
	.byte	0x1
	.byte	0x23
	.long	0x59e
	.uleb128 0x13
	.long	0x91
	.long	.LLST41
	.uleb128 0x18
	.long	.LBB141
	.long	.LBE141-.LBB141
	.uleb128 0x19
	.long	0x9c
	.byte	0
	.byte	0
	.uleb128 0x14
	.long	0x81
	.long	.LBB142
	.long	.LBE142-.LBB142
	.byte	0x1
	.byte	0x23
	.uleb128 0x13
	.long	0x91
	.long	.LLST42
	.uleb128 0x18
	.long	.LBB143
	.long	.LBE143-.LBB143
	.uleb128 0x19
	.long	0x9c
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.uleb128 0x11
	.long	0x149
	.long	.LFB13
	.long	.LFE13-.LFB13
	.uleb128 0x1
	.byte	0x9c
	.long	0x632
	.uleb128 0x1a
	.string	"irq"
	.byte	0x1
	.byte	0x67
	.long	0x4c
	.uleb128 0x2
	.byte	0x91
	.sleb128 0
	.uleb128 0x12
	.long	0xa8
	.long	.LBB144
	.long	.LBE144-.LBB144
	.byte	0x1
	.byte	0x6a
	.long	0x60f
	.uleb128 0x13
	.long	0xbf
	.long	.LLST43
	.uleb128 0x13
	.long	0xb4
	.long	.LLST44
	.byte	0
	.uleb128 0x14
	.long	0xa8
	.long	.LBB146
	.long	.LBE146-.LBB146
	.byte	0x1
	.byte	0x6c
	.uleb128 0x13
	.long	0xbf
	.long	.LLST45
	.uleb128 0x13
	.long	0xb4
	.long	.LLST45
	.byte	0
	.byte	0
	.uleb128 0x1b
	.long	0x15e
	.long	.LFB14
	.long	.LFE14-.LFB14
	.uleb128 0x1
	.byte	0x9c
	.uleb128 0x14
	.long	0xd3
	.long	.LBB148
	.long	.LBE148-.LBB148
	.byte	0x1
	.byte	0x71
	.uleb128 0x13
	.long	0xe3
	.long	.LLST47
	.uleb128 0x12
	.long	0xa8
	.long	.LBB150
	.long	.LBE150-.LBB150
	.byte	0x1
	.byte	0x21
	.long	0x67f
	.uleb128 0x13
	.long	0xbf
	.long	.LLST48
	.uleb128 0x13
	.long	0xb4
	.long	.LLST49
	.byte	0
	.uleb128 0x12
	.long	0xa8
	.long	.LBB152
	.long	.LBE152-.LBB152
	.byte	0x1
	.byte	0x22
	.long	0x6a5
	.uleb128 0x13
	.long	0xbf
	.long	.LLST50
	.uleb128 0x13
	.long	0xb4
	.long	.LLST51
	.byte	0
	.uleb128 0x12
	.long	0x81
	.long	.LBB154
	.long	.LBE154-.LBB154
	.byte	0x1
	.byte	0x23
	.long	0x6d1
	.uleb128 0x13
	.long	0x91
	.long	.LLST52
	.uleb128 0x18
	.long	.LBB155
	.long	.LBE155-.LBB155
	.uleb128 0x19
	.long	0x9c
	.byte	0
	.byte	0
	.uleb128 0x14
	.long	0x81
	.long	.LBB156
	.long	.LBE156-.LBB156
	.byte	0x1
	.byte	0x23
	.uleb128 0x13
	.long	0x91
	.long	.LLST53
	.uleb128 0x18
	.long	.LBB157
	.long	.LBE157-.LBB157
	.uleb128 0x19
	.long	0x9c
	.byte	0
	.byte	0
	.byte	0
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
	.uleb128 0x6
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
	.uleb128 0x7
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
	.uleb128 0x8
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
	.uleb128 0x9
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
	.uleb128 0xa
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
	.uleb128 0xb
	.uleb128 0x2e
	.byte	0x1
	.uleb128 0x3
	.uleb128 0xe
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
	.uleb128 0xc
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
	.uleb128 0xd
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
	.uleb128 0x3c
	.uleb128 0x19
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
	.uleb128 0x6e
	.uleb128 0xe
	.uleb128 0x3c
	.uleb128 0x19
	.uleb128 0x1
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0xf
	.uleb128 0x5
	.byte	0
	.uleb128 0x49
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0x10
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
	.uleb128 0x11
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
	.uleb128 0x12
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
	.uleb128 0x13
	.uleb128 0x5
	.byte	0
	.uleb128 0x31
	.uleb128 0x13
	.uleb128 0x2
	.uleb128 0x17
	.byte	0
	.byte	0
	.uleb128 0x14
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
	.byte	0
	.byte	0
	.uleb128 0x15
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
	.uleb128 0x16
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
	.uleb128 0x17
	.byte	0
	.byte	0
	.uleb128 0x17
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
	.uleb128 0x18
	.uleb128 0xb
	.byte	0x1
	.uleb128 0x11
	.uleb128 0x1
	.uleb128 0x12
	.uleb128 0x6
	.byte	0
	.byte	0
	.uleb128 0x19
	.uleb128 0x34
	.byte	0
	.uleb128 0x31
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0x1a
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
	.uleb128 0x1b
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
	.byte	0
	.byte	0
	.byte	0
	.section	.debug_loc,"",@progbits
.Ldebug_loc0:
.LLST0:
	.long	.LVL0-.Ltext0
	.long	.LVL1-.Ltext0
	.value	0x3
	.byte	0x9
	.byte	0xff
	.byte	0x9f
	.long	0
	.long	0
.LLST1:
	.long	.LVL0-.Ltext0
	.long	.LVL1-.Ltext0
	.value	0x3
	.byte	0x8
	.byte	0xa1
	.byte	0x9f
	.long	0
	.long	0
.LLST2:
	.long	.LVL1-.Ltext0
	.long	.LVL2-.Ltext0
	.value	0x3
	.byte	0x9
	.byte	0xff
	.byte	0x9f
	.long	0
	.long	0
.LLST3:
	.long	.LVL1-.Ltext0
	.long	.LVL2-.Ltext0
	.value	0x3
	.byte	0x8
	.byte	0x21
	.byte	0x9f
	.long	0
	.long	0
.LLST4:
	.long	.LVL3-.Ltext0
	.long	.LVL4-.Ltext0
	.value	0x2
	.byte	0x41
	.byte	0x9f
	.long	0
	.long	0
.LLST5:
	.long	.LVL3-.Ltext0
	.long	.LVL4-.Ltext0
	.value	0x3
	.byte	0x8
	.byte	0x20
	.byte	0x9f
	.long	0
	.long	0
.LLST6:
	.long	.LVL5-.Ltext0
	.long	.LVL6-.Ltext0
	.value	0x2
	.byte	0x41
	.byte	0x9f
	.long	0
	.long	0
.LLST7:
	.long	.LVL5-.Ltext0
	.long	.LVL6-.Ltext0
	.value	0x3
	.byte	0x8
	.byte	0xa0
	.byte	0x9f
	.long	0
	.long	0
.LLST8:
	.long	.LVL7-.Ltext0
	.long	.LVL8-.Ltext0
	.value	0x3
	.byte	0x8
	.byte	0x20
	.byte	0x9f
	.long	0
	.long	0
.LLST9:
	.long	.LVL7-.Ltext0
	.long	.LVL8-.Ltext0
	.value	0x3
	.byte	0x8
	.byte	0x21
	.byte	0x9f
	.long	0
	.long	0
.LLST10:
	.long	.LVL9-.Ltext0
	.long	.LVL10-.Ltext0
	.value	0x3
	.byte	0x8
	.byte	0x28
	.byte	0x9f
	.long	0
	.long	0
.LLST11:
	.long	.LVL9-.Ltext0
	.long	.LVL10-.Ltext0
	.value	0x3
	.byte	0x8
	.byte	0xa1
	.byte	0x9f
	.long	0
	.long	0
.LLST12:
	.long	.LVL11-.Ltext0
	.long	.LVL12-.Ltext0
	.value	0x2
	.byte	0x34
	.byte	0x9f
	.long	0
	.long	0
.LLST13:
	.long	.LVL11-.Ltext0
	.long	.LVL12-.Ltext0
	.value	0x3
	.byte	0x8
	.byte	0x21
	.byte	0x9f
	.long	0
	.long	0
.LLST14:
	.long	.LVL13-.Ltext0
	.long	.LVL14-.Ltext0
	.value	0x2
	.byte	0x32
	.byte	0x9f
	.long	0
	.long	0
.LLST15:
	.long	.LVL13-.Ltext0
	.long	.LVL14-.Ltext0
	.value	0x3
	.byte	0x8
	.byte	0xa1
	.byte	0x9f
	.long	0
	.long	0
.LLST16:
	.long	.LVL15-.Ltext0
	.long	.LVL16-.Ltext0
	.value	0x2
	.byte	0x31
	.byte	0x9f
	.long	0
	.long	0
.LLST17:
	.long	.LVL15-.Ltext0
	.long	.LVL16-.Ltext0
	.value	0x3
	.byte	0x8
	.byte	0x21
	.byte	0x9f
	.long	0
	.long	0
.LLST18:
	.long	.LVL17-.Ltext0
	.long	.LVL18-.Ltext0
	.value	0x2
	.byte	0x31
	.byte	0x9f
	.long	0
	.long	0
.LLST19:
	.long	.LVL17-.Ltext0
	.long	.LVL18-.Ltext0
	.value	0x3
	.byte	0x8
	.byte	0xa1
	.byte	0x9f
	.long	0
	.long	0
.LLST20:
	.long	.LVL19-.Ltext0
	.long	.LVL20-.Ltext0
	.value	0x2
	.byte	0x30
	.byte	0x9f
	.long	0
	.long	0
.LLST21:
	.long	.LVL19-.Ltext0
	.long	.LVL20-.Ltext0
	.value	0x3
	.byte	0x8
	.byte	0x21
	.byte	0x9f
	.long	0
	.long	0
.LLST22:
	.long	.LVL21-.Ltext0
	.long	.LVL22-.Ltext0
	.value	0x2
	.byte	0x30
	.byte	0x9f
	.long	0
	.long	0
.LLST23:
	.long	.LVL21-.Ltext0
	.long	.LVL22-.Ltext0
	.value	0x3
	.byte	0x8
	.byte	0xa1
	.byte	0x9f
	.long	0
	.long	0
.LLST24:
	.long	.LVL23-.Ltext0
	.long	.LVL25-.Ltext0
	.value	0x2
	.byte	0x91
	.sleb128 0
	.long	.LVL25-.Ltext0
	.long	.LVL30-.Ltext0
	.value	0x1
	.byte	0x51
	.long	.LVL30-.Ltext0
	.long	.LFE10-.Ltext0
	.value	0x2
	.byte	0x91
	.sleb128 0
	.long	0
	.long	0
.LLST25:
	.long	.LVL24-.Ltext0
	.long	.LVL26-.Ltext0
	.value	0x3
	.byte	0x8
	.byte	0xa1
	.byte	0x9f
	.long	.LVL26-.Ltext0
	.long	.LVL30-.Ltext0
	.value	0x1
	.byte	0x52
	.long	0
	.long	0
.LLST26:
	.long	.LVL27-.Ltext0
	.long	.LVL28-.Ltext0
	.value	0x15
	.byte	0x9
	.byte	0xfe
	.byte	0x71
	.sleb128 0
	.byte	0xa
	.value	0xffff
	.byte	0x1a
	.byte	0x14
	.byte	0x14
	.byte	0x24
	.byte	0x17
	.byte	0x1f
	.byte	0x23
	.uleb128 0x20
	.byte	0x25
	.byte	0x21
	.byte	0x70
	.sleb128 0
	.byte	0x1a
	.byte	0x9f
	.long	0
	.long	0
.LLST27:
	.long	.LVL26-.Ltext0
	.long	.LVL27-.Ltext0
	.value	0x1
	.byte	0x52
	.long	0
	.long	0
.LLST29:
	.long	.LVL27-.Ltext0
	.long	.LVL29-.Ltext0
	.value	0x1
	.byte	0x52
	.long	0
	.long	0
.LLST30:
	.long	.LVL31-.Ltext0
	.long	.LVL33-.Ltext0
	.value	0x2
	.byte	0x91
	.sleb128 0
	.long	.LVL33-.Ltext0
	.long	.LVL38-.Ltext0
	.value	0x1
	.byte	0x51
	.long	.LVL38-.Ltext0
	.long	.LFE11-.Ltext0
	.value	0x2
	.byte	0x91
	.sleb128 0
	.long	0
	.long	0
.LLST31:
	.long	.LVL32-.Ltext0
	.long	.LVL34-.Ltext0
	.value	0x3
	.byte	0x8
	.byte	0xa1
	.byte	0x9f
	.long	.LVL34-.Ltext0
	.long	.LVL38-.Ltext0
	.value	0x1
	.byte	0x52
	.long	0
	.long	0
.LLST32:
	.long	.LVL35-.Ltext0
	.long	.LVL36-.Ltext0
	.value	0x8
	.byte	0x31
	.byte	0x71
	.sleb128 0
	.byte	0x24
	.byte	0x70
	.sleb128 0
	.byte	0x21
	.byte	0x9f
	.long	0
	.long	0
.LLST33:
	.long	.LVL34-.Ltext0
	.long	.LVL35-.Ltext0
	.value	0x1
	.byte	0x52
	.long	0
	.long	0
.LLST35:
	.long	.LVL35-.Ltext0
	.long	.LVL37-.Ltext0
	.value	0x1
	.byte	0x52
	.long	0
	.long	0
.LLST36:
	.long	.LVL39-.Ltext0
	.long	.LVL43-.Ltext0
	.value	0x2
	.byte	0x3a
	.byte	0x9f
	.long	0
	.long	0
.LLST37:
	.long	.LVL39-.Ltext0
	.long	.LVL40-.Ltext0
	.value	0x2
	.byte	0x3a
	.byte	0x9f
	.long	0
	.long	0
.LLST38:
	.long	.LVL39-.Ltext0
	.long	.LVL40-.Ltext0
	.value	0x3
	.byte	0x8
	.byte	0x20
	.byte	0x9f
	.long	0
	.long	0
.LLST39:
	.long	.LVL40-.Ltext0
	.long	.LVL41-.Ltext0
	.value	0x2
	.byte	0x3a
	.byte	0x9f
	.long	0
	.long	0
.LLST40:
	.long	.LVL40-.Ltext0
	.long	.LVL41-.Ltext0
	.value	0x3
	.byte	0x8
	.byte	0xa0
	.byte	0x9f
	.long	0
	.long	0
.LLST41:
	.long	.LVL41-.Ltext0
	.long	.LVL42-.Ltext0
	.value	0x3
	.byte	0x8
	.byte	0xa0
	.byte	0x9f
	.long	0
	.long	0
.LLST42:
	.long	.LVL42-.Ltext0
	.long	.LVL43-.Ltext0
	.value	0x3
	.byte	0x8
	.byte	0x20
	.byte	0x9f
	.long	0
	.long	0
.LLST43:
	.long	.LVL45-.Ltext0
	.long	.LVL46-.Ltext0
	.value	0x3
	.byte	0x8
	.byte	0x20
	.byte	0x9f
	.long	0
	.long	0
.LLST44:
	.long	.LVL45-.Ltext0
	.long	.LVL46-.Ltext0
	.value	0x3
	.byte	0x8
	.byte	0xa0
	.byte	0x9f
	.long	0
	.long	0
.LLST45:
	.long	.LVL46-.Ltext0
	.long	.LVL47-.Ltext0
	.value	0x3
	.byte	0x8
	.byte	0x20
	.byte	0x9f
	.long	0
	.long	0
.LLST47:
	.long	.LVL48-.Ltext0
	.long	.LVL52-.Ltext0
	.value	0x2
	.byte	0x3b
	.byte	0x9f
	.long	0
	.long	0
.LLST48:
	.long	.LVL48-.Ltext0
	.long	.LVL49-.Ltext0
	.value	0x2
	.byte	0x3b
	.byte	0x9f
	.long	0
	.long	0
.LLST49:
	.long	.LVL48-.Ltext0
	.long	.LVL49-.Ltext0
	.value	0x3
	.byte	0x8
	.byte	0x20
	.byte	0x9f
	.long	0
	.long	0
.LLST50:
	.long	.LVL49-.Ltext0
	.long	.LVL50-.Ltext0
	.value	0x2
	.byte	0x3b
	.byte	0x9f
	.long	0
	.long	0
.LLST51:
	.long	.LVL49-.Ltext0
	.long	.LVL50-.Ltext0
	.value	0x3
	.byte	0x8
	.byte	0xa0
	.byte	0x9f
	.long	0
	.long	0
.LLST52:
	.long	.LVL50-.Ltext0
	.long	.LVL51-.Ltext0
	.value	0x3
	.byte	0x8
	.byte	0xa0
	.byte	0x9f
	.long	0
	.long	0
.LLST53:
	.long	.LVL51-.Ltext0
	.long	.LVL52-.Ltext0
	.value	0x3
	.byte	0x8
	.byte	0x20
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
.LASF14:
	.string	"Disable"
.LASF28:
	.string	"value"
.LASF12:
	.string	"__pic_get_irq_reg"
.LASF24:
	.string	"GetIRR"
.LASF20:
	.string	"_ZN3PIC9UnmaskIRQEt"
.LASF15:
	.string	"Remap"
.LASF21:
	.string	"_ZN3PIC7MaskIRQEt"
.LASF30:
	.string	"GNU C++11 5.3.0 -mtune=generic -march=pentiumpro -g -O2 -std=c++11 -ffreestanding -fbuiltin -fstack-protector-strong -fno-exceptions -fno-rtti"
.LASF18:
	.string	"UnmaskIRQ"
.LASF17:
	.string	"_ZN3PIC5RemapEv"
.LASF4:
	.string	"unsigned char"
.LASF8:
	.string	"long unsigned int"
.LASF7:
	.string	"short unsigned int"
.LASF31:
	.string	"arch/i386/pic.cpp"
.LASF32:
	.string	"/home/pfalcato/Spartix/kernel"
.LASF26:
	.string	"_ZN3PIC6GetIRREv"
.LASF13:
	.string	"ocw3"
.LASF33:
	.string	"outb"
.LASF10:
	.string	"unsigned int"
.LASF9:
	.string	"long long unsigned int"
.LASF5:
	.string	"uint8_t"
.LASF16:
	.string	"_ZN3PIC7DisableEv"
.LASF23:
	.string	"_ZN3PIC7SendEOIEh"
.LASF25:
	.string	"GetISR"
.LASF22:
	.string	"SendEOI"
.LASF19:
	.string	"MaskIRQ"
.LASF3:
	.string	"long long int"
.LASF29:
	.string	"irqn"
.LASF11:
	.string	"port"
.LASF1:
	.string	"short int"
.LASF6:
	.string	"uint16_t"
.LASF2:
	.string	"long int"
.LASF27:
	.string	"_ZN3PIC6GetISREv"
.LASF0:
	.string	"signed char"
.LASF34:
	.string	"io_wait"
	.ident	"GCC: (GNU) 5.3.0"
