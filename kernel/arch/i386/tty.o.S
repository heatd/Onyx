	.file	"tty.cpp"
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
	.globl	_ZN3TTY4InitEv
	.type	_ZN3TTY4InitEv, @function
_ZN3TTY4InitEv:
.LFB9:
	.file 1 "arch/i386/tty.cpp"
	.loc 1 39 0
	.cfi_startproc
	.loc 1 40 0
	movl	$0, terminal_row
	.loc 1 41 0
	movl	$0, terminal_column
	.loc 1 43 0
	movl	$-2146729984, %eax
	.loc 1 42 0
	movb	$7, terminal_color
	.loc 1 43 0
	movl	$-2146729984, terminal_buffer
.LVL0:
	.align 16
.L3:
	leal	160(%eax), %edx
.LVL1:
	.align 16
.L2:
.LBB70:
.LBB71:
.LBB72:
	.loc 1 49 0 discriminator 2
	movl	$1824, %ecx
	addl	$2, %eax
	movw	%cx, -2(%eax)
.LBE72:
	.loc 1 46 0 discriminator 2
	cmpl	%edx, %eax
	jne	.L2
.LBE71:
	.loc 1 44 0 discriminator 2
	cmpl	$-2146725984, %eax
	jne	.L3
.LBE70:
	.loc 1 52 0
	rep ret
	.cfi_endproc
.LFE9:
	.size	_ZN3TTY4InitEv, .-_ZN3TTY4InitEv
	.section	.text.unlikely
.LCOLDE0:
	.text
.LHOTE0:
	.section	.text.unlikely
.LCOLDB1:
	.text
.LHOTB1:
	.align 16
	.globl	_ZN3TTY8SetColorEh
	.type	_ZN3TTY8SetColorEh, @function
_ZN3TTY8SetColorEh:
.LFB10:
	.loc 1 55 0
	.cfi_startproc
.LVL2:
	.loc 1 56 0
	movl	4(%esp), %eax
	movb	%al, terminal_color
	ret
	.cfi_endproc
.LFE10:
	.size	_ZN3TTY8SetColorEh, .-_ZN3TTY8SetColorEh
	.section	.text.unlikely
.LCOLDE1:
	.text
.LHOTE1:
	.section	.text.unlikely
.LCOLDB2:
	.text
.LHOTB2:
	.align 16
	.globl	_Z19terminal_putentryatchmm
	.type	_Z19terminal_putentryatchmm, @function
_Z19terminal_putentryatchmm:
.LFB11:
	.loc 1 60 0
	.cfi_startproc
.LVL3:
	.loc 1 60 0
	movl	16(%esp), %eax
.LVL4:
	.loc 1 62 0
	movzbl	8(%esp), %edx
	movsbw	4(%esp), %cx
.LVL5:
	leal	(%eax,%eax,4), %eax
	sall	$8, %edx
	sall	$4, %eax
	addl	12(%esp), %eax
	orl	%ecx, %edx
	movl	terminal_buffer, %ecx
.LVL6:
	movw	%dx, (%ecx,%eax,2)
	ret
	.cfi_endproc
.LFE11:
	.size	_Z19terminal_putentryatchmm, .-_Z19terminal_putentryatchmm
	.section	.text.unlikely
.LCOLDE2:
	.text
.LHOTE2:
	.section	.text.unlikely
.LCOLDB3:
	.text
.LHOTB3:
	.align 16
	.globl	_Z15terminal_scrollv
	.type	_Z15terminal_scrollv, @function
_Z15terminal_scrollv:
.LFB12:
	.loc 1 65 0
	.cfi_startproc
.LVL7:
	movl	terminal_buffer, %eax
	pushl	%ebx
	.cfi_def_cfa_offset 8
	.cfi_offset 3, -8
	.loc 1 65 0
	movl	$80, %ebx
	addl	$160, %eax
.LVL8:
	.align 16
.L11:
	leal	160(%eax), %ecx
.LVL9:
	.align 16
.L10:
.LBB73:
.LBB74:
	.loc 1 68 0 discriminator 2
	movzwl	(%eax), %edx
	addl	$2, %eax
	movw	%dx, -162(%eax)
	.loc 1 67 0 discriminator 2
	cmpl	%eax, %ecx
	jne	.L10
	addl	$80, %ebx
	movl	%ecx, %eax
.LBE74:
	.loc 1 66 0 discriminator 2
	cmpl	$2080, %ebx
	jne	.L11
.LBE73:
	.loc 1 71 0
	popl	%ebx
	.cfi_restore 3
	.cfi_def_cfa_offset 4
	ret
	.cfi_endproc
.LFE12:
	.size	_Z15terminal_scrollv, .-_Z15terminal_scrollv
	.section	.text.unlikely
.LCOLDE3:
	.text
.LHOTE3:
	.section	.text.unlikely
.LCOLDB4:
	.text
.LHOTB4:
	.align 16
	.globl	_ZN3TTY7PutCharEc
	.type	_ZN3TTY7PutCharEc, @function
_ZN3TTY7PutCharEc:
.LFB13:
	.loc 1 73 0
	.cfi_startproc
.LVL10:
	pushl	%edi
	.cfi_def_cfa_offset 8
	.cfi_offset 7, -8
	pushl	%esi
	.cfi_def_cfa_offset 12
	.cfi_offset 6, -12
	pushl	%ebx
	.cfi_def_cfa_offset 16
	.cfi_offset 3, -16
	.loc 1 73 0
	movl	16(%esp), %edi
	.loc 1 74 0
	movl	%edi, %eax
	cmpb	$10, %al
	je	.L25
.LBB115:
.LBB116:
	.loc 1 62 0
	movzbl	terminal_color, %ebx
.LBE116:
.LBE115:
	.loc 1 84 0
	movl	terminal_row, %ecx
	movl	terminal_column, %eax
.LVL11:
.LBB119:
.LBB117:
	.loc 1 62 0
	leal	(%ecx,%ecx,4), %edx
	movl	%ebx, %esi
	movl	%edi, %ebx
	sall	$8, %esi
	movsbw	%bl, %bx
.LVL12:
	sall	$4, %edx
	orl	%esi, %ebx
.LVL13:
	movl	terminal_buffer, %esi
	addl	%eax, %edx
.LBE117:
.LBE119:
	.loc 1 85 0
	addl	$1, %eax
.LVL14:
	cmpl	$80, %eax
.LBB120:
.LBB118:
	.loc 1 62 0
	movw	%bx, (%esi,%edx,2)
.LVL15:
.LBE118:
.LBE120:
	.loc 1 85 0
	je	.L20
	movl	%eax, terminal_column
.L21:
.LBB121:
.LBB122:
	.loc 1 97 0
	leal	(%ecx,%ecx,4), %ecx
	sall	$4, %ecx
	addl	%eax, %ecx
.LVL16:
.L24:
.LBB123:
.LBB124:
	.file 2 "include/kernel/portio.h"
	.loc 2 22 0
	movl	$980, %esi
	movl	$15, %eax
	movl	%esi, %edx
/APP
/  22 "include/kernel/portio.h" 1
	outb %al, %dx
/  0 "" 2
.LVL17:
/NO_APP
.LBE124:
.LBE123:
.LBB125:
.LBB126:
	movl	$981, %ebx
	movl	%ecx, %eax
	movl	%ebx, %edx
/APP
/  22 "include/kernel/portio.h" 1
	outb %al, %dx
/  0 "" 2
.LVL18:
/NO_APP
.LBE126:
.LBE125:
.LBB127:
.LBB128:
	movl	$14, %eax
	movl	%esi, %edx
/APP
/  22 "include/kernel/portio.h" 1
	outb %al, %dx
/  0 "" 2
.LVL19:
/NO_APP
.LBE128:
.LBE127:
.LBB129:
.LBB130:
	movl	%ecx, %eax
	movl	%ebx, %edx
	shrw	$8, %ax
/APP
/  22 "include/kernel/portio.h" 1
	outb %al, %dx
/  0 "" 2
.LVL20:
/NO_APP
.LBE130:
.LBE129:
.LBE122:
.LBE121:
	.loc 1 94 0
	popl	%ebx
	.cfi_remember_state
	.cfi_restore 3
	.cfi_def_cfa_offset 12
	popl	%esi
	.cfi_restore 6
	.cfi_def_cfa_offset 8
	popl	%edi
	.cfi_restore 7
	.cfi_def_cfa_offset 4
	ret
.LVL21:
	.align 16
.L25:
	.cfi_restore_state
.LBB131:
.LBB132:
	.loc 1 76 0
	movl	terminal_row, %edx
	.loc 1 75 0
	movl	$0, terminal_column
	.loc 1 76 0
	cmpl	$24, %edx
	je	.L26
	.loc 1 79 0
	addl	$1, %edx
	xorl	%ecx, %ecx
	movl	%edx, terminal_row
.L18:
.LBB133:
.LBB134:
	.loc 1 97 0
	leal	(%edx,%edx,4), %edx
	sall	$4, %edx
	addl	%edx, %ecx
.LVL22:
	jmp	.L24
.LVL23:
	.align 16
.L20:
.LBE134:
.LBE133:
.LBE132:
.LBE131:
	.loc 1 88 0
	addl	$1, %ecx
	xorl	%eax, %eax
	.loc 1 87 0
	movl	$0, terminal_column
	.loc 1 88 0
	cmpl	$25, %ecx
	movl	%ecx, terminal_row
	jne	.L21
	.loc 1 90 0
	call	_Z15terminal_scrollv
.LVL24:
	movl	terminal_row, %ecx
	movzwl	terminal_column, %eax
	jmp	.L21
.LVL25:
	.align 16
.L26:
.LBB136:
.LBB135:
	.loc 1 77 0
	call	_Z15terminal_scrollv
.LVL26:
	movl	terminal_row, %edx
	movzwl	terminal_column, %ecx
	jmp	.L18
.LBE135:
.LBE136:
	.cfi_endproc
.LFE13:
	.size	_ZN3TTY7PutCharEc, .-_ZN3TTY7PutCharEc
	.section	.text.unlikely
.LCOLDE4:
	.text
.LHOTE4:
	.section	.text.unlikely
.LCOLDB5:
	.text
.LHOTB5:
	.align 16
	.globl	_ZN3TTY12UpdateCursorEv
	.type	_ZN3TTY12UpdateCursorEv, @function
_ZN3TTY12UpdateCursorEv:
.LFB14:
	.loc 1 96 0
	.cfi_startproc
	.loc 1 97 0
	movl	terminal_row, %ecx
.LBB137:
.LBB138:
	.loc 2 22 0
	movl	$980, %edx
	movl	$15, %eax
.LBE138:
.LBE137:
	.loc 1 97 0
	leal	(%ecx,%ecx,4), %ecx
	sall	$4, %ecx
	addw	terminal_column, %cx
.LVL27:
.LBB140:
.LBB139:
	.loc 2 22 0
/APP
/  22 "include/kernel/portio.h" 1
	outb %al, %dx
/  0 "" 2
.LVL28:
/NO_APP
.LBE139:
.LBE140:
.LBB141:
.LBB142:
	movl	$981, %edx
	movl	%ecx, %eax
/APP
/  22 "include/kernel/portio.h" 1
	outb %al, %dx
/  0 "" 2
.LVL29:
/NO_APP
.LBE142:
.LBE141:
.LBB143:
.LBB144:
	movl	$980, %edx
	movl	$14, %eax
/APP
/  22 "include/kernel/portio.h" 1
	outb %al, %dx
/  0 "" 2
.LVL30:
/NO_APP
.LBE144:
.LBE143:
.LBB145:
.LBB146:
	movl	%ecx, %eax
	movl	$981, %edx
	shrw	$8, %ax
/APP
/  22 "include/kernel/portio.h" 1
	outb %al, %dx
/  0 "" 2
.LVL31:
/NO_APP
	ret
.LBE146:
.LBE145:
	.cfi_endproc
.LFE14:
	.size	_ZN3TTY12UpdateCursorEv, .-_ZN3TTY12UpdateCursorEv
	.section	.text.unlikely
.LCOLDE5:
	.text
.LHOTE5:
	.section	.text.unlikely
.LCOLDB6:
	.text
.LHOTB6:
	.align 16
	.globl	_ZN3TTY5WriteEPKcm
	.type	_ZN3TTY5WriteEPKcm, @function
_ZN3TTY5WriteEPKcm:
.LFB15:
	.loc 1 104 0
	.cfi_startproc
.LVL32:
	pushl	%esi
	.cfi_def_cfa_offset 8
	.cfi_offset 6, -8
	pushl	%ebx
	.cfi_def_cfa_offset 12
	.cfi_offset 3, -12
.LVL33:
	.loc 1 104 0
	movl	16(%esp), %eax
	movl	12(%esp), %ebx
.LBB147:
	.loc 1 105 0
	testl	%eax, %eax
	leal	(%ebx,%eax), %esi
	je	.L28
.LVL34:
	.align 16
.L32:
	.loc 1 106 0 discriminator 2
	movsbl	(%ebx), %eax
	addl	$1, %ebx
.LVL35:
	pushl	%eax
	.cfi_def_cfa_offset 16
	call	_ZN3TTY7PutCharEc
.LVL36:
	.loc 1 105 0 discriminator 2
	cmpl	%esi, %ebx
	popl	%eax
	.cfi_def_cfa_offset 12
	jne	.L32
.L28:
.LBE147:
	.loc 1 107 0
	popl	%ebx
	.cfi_restore 3
	.cfi_def_cfa_offset 8
	popl	%esi
	.cfi_restore 6
	.cfi_def_cfa_offset 4
	ret
	.cfi_endproc
.LFE15:
	.size	_ZN3TTY5WriteEPKcm, .-_ZN3TTY5WriteEPKcm
	.section	.text.unlikely
.LCOLDE6:
	.text
.LHOTE6:
	.section	.text.unlikely
.LCOLDB7:
	.text
.LHOTB7:
	.align 16
	.globl	_ZN3TTY11WriteStringEPKc
	.type	_ZN3TTY11WriteStringEPKc, @function
_ZN3TTY11WriteStringEPKc:
.LFB16:
	.loc 1 110 0
	.cfi_startproc
.LVL37:
	pushl	%esi
	.cfi_def_cfa_offset 8
	.cfi_offset 6, -8
	pushl	%ebx
	.cfi_def_cfa_offset 12
	.cfi_offset 3, -12
	subl	$16, %esp
	.cfi_def_cfa_offset 28
	.loc 1 110 0
	movl	28(%esp), %ebx
	.loc 1 111 0
	pushl	%ebx
	.cfi_def_cfa_offset 32
	call	strlen
.LVL38:
	addl	$16, %esp
	.cfi_def_cfa_offset 16
.LVL39:
.LBB148:
.LBB149:
	.loc 1 105 0
	testl	%eax, %eax
	leal	(%ebx,%eax), %esi
	je	.L34
.LVL40:
	.align 16
.L38:
	.loc 1 106 0
	movsbl	(%ebx), %eax
	subl	$12, %esp
	.cfi_def_cfa_offset 28
	addl	$1, %ebx
.LVL41:
	pushl	%eax
	.cfi_def_cfa_offset 32
	call	_ZN3TTY7PutCharEc
.LVL42:
	.loc 1 105 0
	addl	$16, %esp
	.cfi_def_cfa_offset 16
	cmpl	%esi, %ebx
	jne	.L38
.L34:
.LBE149:
.LBE148:
	.loc 1 112 0
	addl	$4, %esp
	.cfi_def_cfa_offset 12
	popl	%ebx
	.cfi_restore 3
	.cfi_def_cfa_offset 8
	popl	%esi
	.cfi_restore 6
	.cfi_def_cfa_offset 4
	ret
	.cfi_endproc
.LFE16:
	.size	_ZN3TTY11WriteStringEPKc, .-_ZN3TTY11WriteStringEPKc
	.section	.text.unlikely
.LCOLDE7:
	.text
.LHOTE7:
	.globl	terminal_buffer
	.section	.bss
	.align 4
	.type	terminal_buffer, @object
	.size	terminal_buffer, 4
terminal_buffer:
	.zero	4
	.globl	terminal_color
	.type	terminal_color, @object
	.size	terminal_color, 1
terminal_color:
	.zero	1
	.globl	terminal_column
	.align 4
	.type	terminal_column, @object
	.size	terminal_column, 4
terminal_column:
	.zero	4
	.globl	terminal_row
	.align 4
	.type	terminal_row, @object
	.size	terminal_row, 4
terminal_row:
	.zero	4
	.text
.Letext0:
	.section	.text.unlikely
.Letext_cold0:
	.file 3 "/home/pfalcato/i686-elf/lib/gcc/i686-elf/5.3.0/include/stddef.h"
	.file 4 "/home/pfalcato/i686-elf/lib/gcc/i686-elf/5.3.0/include/stdint-gcc.h"
	.file 5 "include/kernel/vga.h"
	.file 6 "include/kernel/tty.h"
	.file 7 "/home/pfalcato/Spartix/sysroot/usr/include/string.h"
	.section	.debug_info,"",@progbits
.Ldebug_info0:
	.long	0x709
	.value	0x4
	.long	.Ldebug_abbrev0
	.byte	0x4
	.uleb128 0x1
	.long	.LASF58
	.byte	0x4
	.long	.LASF59
	.long	.LASF60
	.long	.Ltext0
	.long	.Letext0-.Ltext0
	.long	.Ldebug_line0
	.uleb128 0x2
	.byte	0x4
	.byte	0x5
	.long	.LASF0
	.uleb128 0x3
	.long	.LASF6
	.byte	0x3
	.byte	0xd8
	.long	0x37
	.uleb128 0x2
	.byte	0x4
	.byte	0x7
	.long	.LASF1
	.uleb128 0x2
	.byte	0x8
	.byte	0x5
	.long	.LASF2
	.uleb128 0x2
	.byte	0xc
	.byte	0x4
	.long	.LASF3
	.uleb128 0x4
	.long	.LASF61
	.uleb128 0x2
	.byte	0x1
	.byte	0x6
	.long	.LASF4
	.uleb128 0x2
	.byte	0x2
	.byte	0x5
	.long	.LASF5
	.uleb128 0x3
	.long	.LASF7
	.byte	0x4
	.byte	0x2e
	.long	0x6a
	.uleb128 0x2
	.byte	0x1
	.byte	0x8
	.long	.LASF8
	.uleb128 0x3
	.long	.LASF9
	.byte	0x4
	.byte	0x31
	.long	0x7c
	.uleb128 0x2
	.byte	0x2
	.byte	0x7
	.long	.LASF10
	.uleb128 0x2
	.byte	0x8
	.byte	0x7
	.long	.LASF11
	.uleb128 0x5
	.byte	0x4
	.byte	0x5
	.string	"int"
	.uleb128 0x2
	.byte	0x4
	.byte	0x7
	.long	.LASF12
	.uleb128 0x6
	.long	.LASF62
	.byte	0x4
	.long	0x91
	.byte	0x5
	.byte	0x14
	.long	0x109
	.uleb128 0x7
	.long	.LASF13
	.byte	0
	.uleb128 0x7
	.long	.LASF14
	.byte	0x1
	.uleb128 0x7
	.long	.LASF15
	.byte	0x2
	.uleb128 0x7
	.long	.LASF16
	.byte	0x3
	.uleb128 0x7
	.long	.LASF17
	.byte	0x4
	.uleb128 0x7
	.long	.LASF18
	.byte	0x5
	.uleb128 0x7
	.long	.LASF19
	.byte	0x6
	.uleb128 0x7
	.long	.LASF20
	.byte	0x7
	.uleb128 0x7
	.long	.LASF21
	.byte	0x8
	.uleb128 0x7
	.long	.LASF22
	.byte	0x9
	.uleb128 0x7
	.long	.LASF23
	.byte	0xa
	.uleb128 0x7
	.long	.LASF24
	.byte	0xb
	.uleb128 0x7
	.long	.LASF25
	.byte	0xc
	.uleb128 0x7
	.long	.LASF26
	.byte	0xd
	.uleb128 0x7
	.long	.LASF27
	.byte	0xe
	.uleb128 0x7
	.long	.LASF28
	.byte	0xf
	.byte	0
	.uleb128 0x8
	.long	.LASF29
	.byte	0x5
	.byte	0x28
	.long	0x5f
	.byte	0x3
	.long	0x12e
	.uleb128 0x9
	.string	"fg"
	.byte	0x5
	.byte	0x28
	.long	0x98
	.uleb128 0x9
	.string	"bg"
	.byte	0x5
	.byte	0x28
	.long	0x98
	.byte	0
	.uleb128 0x8
	.long	.LASF30
	.byte	0x5
	.byte	0x2d
	.long	0x71
	.byte	0x3
	.long	0x169
	.uleb128 0x9
	.string	"c"
	.byte	0x5
	.byte	0x2d
	.long	0x169
	.uleb128 0xa
	.long	.LASF31
	.byte	0x5
	.byte	0x2d
	.long	0x5f
	.uleb128 0xb
	.string	"c16"
	.byte	0x5
	.byte	0x2f
	.long	0x71
	.uleb128 0xc
	.long	.LASF32
	.byte	0x5
	.byte	0x30
	.long	0x71
	.byte	0
	.uleb128 0x2
	.byte	0x1
	.byte	0x6
	.long	.LASF33
	.uleb128 0xd
	.long	.LASF63
	.byte	0x2
	.byte	0x14
	.byte	0x3
	.long	0x193
	.uleb128 0xa
	.long	.LASF34
	.byte	0x2
	.byte	0x14
	.long	0x71
	.uleb128 0x9
	.string	"val"
	.byte	0x2
	.byte	0x14
	.long	0x5f
	.byte	0
	.uleb128 0xe
	.string	"TTY"
	.byte	0x6
	.byte	0x14
	.long	0x20a
	.uleb128 0xf
	.long	.LASF39
	.byte	0x1
	.byte	0x5f
	.long	.LASF41
	.uleb128 0x10
	.long	.LASF35
	.byte	0x1
	.byte	0x48
	.long	.LASF37
	.long	0x1be
	.uleb128 0x11
	.long	0x169
	.byte	0
	.uleb128 0x10
	.long	.LASF36
	.byte	0x1
	.byte	0x67
	.long	.LASF38
	.long	0x1d8
	.uleb128 0x11
	.long	0x27b
	.uleb128 0x11
	.long	0x2c
	.byte	0
	.uleb128 0xf
	.long	.LASF40
	.byte	0x1
	.byte	0x26
	.long	.LASF42
	.uleb128 0x10
	.long	.LASF43
	.byte	0x1
	.byte	0x36
	.long	.LASF44
	.long	0x1f8
	.uleb128 0x11
	.long	0x5f
	.byte	0
	.uleb128 0x12
	.long	.LASF64
	.byte	0x1
	.byte	0x6d
	.long	.LASF65
	.uleb128 0x11
	.long	0x27b
	.byte	0
	.byte	0
	.uleb128 0x13
	.long	0x19e
	.byte	0x1
	.long	0x220
	.uleb128 0xc
	.long	.LASF45
	.byte	0x1
	.byte	0x61
	.long	0x71
	.byte	0
	.uleb128 0x14
	.long	.LASF46
	.byte	0x1
	.byte	0x3b
	.long	.LASF47
	.byte	0x1
	.long	0x262
	.uleb128 0x9
	.string	"c"
	.byte	0x1
	.byte	0x3b
	.long	0x169
	.uleb128 0xa
	.long	.LASF31
	.byte	0x1
	.byte	0x3b
	.long	0x5f
	.uleb128 0x9
	.string	"x"
	.byte	0x1
	.byte	0x3b
	.long	0x2c
	.uleb128 0x9
	.string	"y"
	.byte	0x1
	.byte	0x3b
	.long	0x2c
	.uleb128 0xc
	.long	.LASF48
	.byte	0x1
	.byte	0x3d
	.long	0x262
	.byte	0
	.uleb128 0x15
	.long	0x2c
	.uleb128 0x13
	.long	0x1a9
	.byte	0x1
	.long	0x27b
	.uleb128 0x9
	.string	"c"
	.byte	0x1
	.byte	0x48
	.long	0x169
	.byte	0
	.uleb128 0x16
	.byte	0x4
	.long	0x281
	.uleb128 0x15
	.long	0x169
	.uleb128 0x13
	.long	0x1be
	.byte	0x1
	.long	0x2b2
	.uleb128 0xa
	.long	.LASF49
	.byte	0x1
	.byte	0x67
	.long	0x27b
	.uleb128 0xa
	.long	.LASF50
	.byte	0x1
	.byte	0x67
	.long	0x2c
	.uleb128 0x17
	.uleb128 0xb
	.string	"i"
	.byte	0x1
	.byte	0x69
	.long	0x2c
	.byte	0
	.byte	0
	.uleb128 0x18
	.long	0x1d8
	.long	.LFB9
	.long	.LFE9-.LFB9
	.uleb128 0x1
	.byte	0x9c
	.long	0x305
	.uleb128 0x19
	.long	.LBB70
	.long	.LBE70-.LBB70
	.uleb128 0xb
	.string	"y"
	.byte	0x1
	.byte	0x2c
	.long	0x2c
	.uleb128 0x19
	.long	.LBB71
	.long	.LBE71-.LBB71
	.uleb128 0x1a
	.string	"x"
	.byte	0x1
	.byte	0x2e
	.long	0x2c
	.long	.LLST0
	.uleb128 0x19
	.long	.LBB72
	.long	.LBE72-.LBB72
	.uleb128 0xc
	.long	.LASF48
	.byte	0x1
	.byte	0x30
	.long	0x262
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.uleb128 0x18
	.long	0x1e3
	.long	.LFB10
	.long	.LFE10-.LFB10
	.uleb128 0x1
	.byte	0x9c
	.long	0x327
	.uleb128 0x1b
	.long	.LASF31
	.byte	0x1
	.byte	0x36
	.long	0x5f
	.uleb128 0x2
	.byte	0x91
	.sleb128 0
	.byte	0
	.uleb128 0x1c
	.long	0x220
	.long	.LASF47
	.long	.LFB11
	.long	.LFE11-.LFB11
	.uleb128 0x1
	.byte	0x9c
	.long	0x370
	.uleb128 0x1d
	.long	0x230
	.uleb128 0x2
	.byte	0x91
	.sleb128 0
	.uleb128 0x1d
	.long	0x239
	.uleb128 0x2
	.byte	0x91
	.sleb128 4
	.uleb128 0x1d
	.long	0x244
	.uleb128 0x2
	.byte	0x91
	.sleb128 8
	.uleb128 0x1d
	.long	0x24d
	.uleb128 0x2
	.byte	0x91
	.sleb128 12
	.uleb128 0x1e
	.long	0x256
	.uleb128 0xb
	.byte	0x91
	.sleb128 12
	.byte	0x6
	.byte	0x8
	.byte	0x50
	.byte	0x1e
	.byte	0x91
	.sleb128 8
	.byte	0x6
	.byte	0x22
	.byte	0x9f
	.byte	0
	.uleb128 0x1f
	.long	.LASF66
	.byte	0x1
	.byte	0x40
	.long	.LASF67
	.long	.LFB12
	.long	.LFE12-.LFB12
	.uleb128 0x1
	.byte	0x9c
	.long	0x3b8
	.uleb128 0x19
	.long	.LBB73
	.long	.LBE73-.LBB73
	.uleb128 0x1a
	.string	"i"
	.byte	0x1
	.byte	0x42
	.long	0x91
	.long	.LLST1
	.uleb128 0x19
	.long	.LBB74
	.long	.LBE74-.LBB74
	.uleb128 0x1a
	.string	"m"
	.byte	0x1
	.byte	0x43
	.long	0x91
	.long	.LLST2
	.byte	0
	.byte	0
	.byte	0
	.uleb128 0x1c
	.long	0x267
	.long	.LASF37
	.long	.LFB13
	.long	.LFE13-.LFB13
	.uleb128 0x1
	.byte	0x9c
	.long	0x526
	.uleb128 0x1d
	.long	0x271
	.uleb128 0x2
	.byte	0x91
	.sleb128 0
	.uleb128 0x20
	.long	0x220
	.long	.LBB115
	.long	.Ldebug_ranges0+0
	.byte	0x1
	.byte	0x54
	.long	0x41e
	.uleb128 0x21
	.long	0x24d
	.long	.LLST3
	.uleb128 0x21
	.long	0x244
	.long	.LLST4
	.uleb128 0x21
	.long	0x239
	.long	.LLST5
	.uleb128 0x21
	.long	0x230
	.long	.LLST6
	.uleb128 0x22
	.long	.Ldebug_ranges0+0
	.uleb128 0x23
	.long	0x256
	.long	.LLST7
	.byte	0
	.byte	0
	.uleb128 0x24
	.long	0x20a
	.long	.LBB121
	.long	.LBE121-.LBB121
	.byte	0x1
	.byte	0x5d
	.long	0x4d9
	.uleb128 0x19
	.long	.LBB122
	.long	.LBE122-.LBB122
	.uleb128 0x23
	.long	0x214
	.long	.LLST8
	.uleb128 0x24
	.long	0x170
	.long	.LBB123
	.long	.LBE123-.LBB123
	.byte	0x1
	.byte	0x62
	.long	0x469
	.uleb128 0x21
	.long	0x187
	.long	.LLST9
	.uleb128 0x21
	.long	0x17c
	.long	.LLST10
	.byte	0
	.uleb128 0x24
	.long	0x170
	.long	.LBB125
	.long	.LBE125-.LBB125
	.byte	0x1
	.byte	0x63
	.long	0x48f
	.uleb128 0x21
	.long	0x187
	.long	.LLST11
	.uleb128 0x21
	.long	0x17c
	.long	.LLST12
	.byte	0
	.uleb128 0x24
	.long	0x170
	.long	.LBB127
	.long	.LBE127-.LBB127
	.byte	0x1
	.byte	0x64
	.long	0x4b5
	.uleb128 0x21
	.long	0x187
	.long	.LLST13
	.uleb128 0x21
	.long	0x17c
	.long	.LLST14
	.byte	0
	.uleb128 0x25
	.long	0x170
	.long	.LBB129
	.long	.LBE129-.LBB129
	.byte	0x1
	.byte	0x65
	.uleb128 0x21
	.long	0x187
	.long	.LLST15
	.uleb128 0x21
	.long	0x17c
	.long	.LLST16
	.byte	0
	.byte	0
	.byte	0
	.uleb128 0x26
	.long	.Ldebug_ranges0+0x20
	.long	0x51c
	.uleb128 0x21
	.long	0x271
	.long	.LLST17
	.uleb128 0x24
	.long	0x20a
	.long	.LBB133
	.long	.LBE133-.LBB133
	.byte	0x1
	.byte	0x51
	.long	0x512
	.uleb128 0x19
	.long	.LBB134
	.long	.LBE134-.LBB134
	.uleb128 0x23
	.long	0x214
	.long	.LLST18
	.byte	0
	.byte	0
	.uleb128 0x27
	.long	.LVL26
	.long	0x370
	.byte	0
	.uleb128 0x27
	.long	.LVL24
	.long	0x370
	.byte	0
	.uleb128 0x1c
	.long	0x20a
	.long	.LASF41
	.long	.LFB14
	.long	.LFE14-.LFB14
	.uleb128 0x1
	.byte	0x9c
	.long	0x5d9
	.uleb128 0x1e
	.long	0x214
	.uleb128 0x1
	.byte	0x51
	.uleb128 0x20
	.long	0x170
	.long	.LBB137
	.long	.Ldebug_ranges0+0x38
	.byte	0x1
	.byte	0x62
	.long	0x56a
	.uleb128 0x21
	.long	0x187
	.long	.LLST19
	.uleb128 0x21
	.long	0x17c
	.long	.LLST20
	.byte	0
	.uleb128 0x24
	.long	0x170
	.long	.LBB141
	.long	.LBE141-.LBB141
	.byte	0x1
	.byte	0x63
	.long	0x590
	.uleb128 0x21
	.long	0x187
	.long	.LLST21
	.uleb128 0x21
	.long	0x17c
	.long	.LLST22
	.byte	0
	.uleb128 0x24
	.long	0x170
	.long	.LBB143
	.long	.LBE143-.LBB143
	.byte	0x1
	.byte	0x64
	.long	0x5b6
	.uleb128 0x21
	.long	0x187
	.long	.LLST23
	.uleb128 0x21
	.long	0x17c
	.long	.LLST24
	.byte	0
	.uleb128 0x25
	.long	0x170
	.long	.LBB145
	.long	.LBE145-.LBB145
	.byte	0x1
	.byte	0x65
	.uleb128 0x21
	.long	0x187
	.long	.LLST25
	.uleb128 0x21
	.long	0x17c
	.long	.LLST26
	.byte	0
	.byte	0
	.uleb128 0x1c
	.long	0x286
	.long	.LASF38
	.long	.LFB15
	.long	.LFE15-.LFB15
	.uleb128 0x1
	.byte	0x9c
	.long	0x61d
	.uleb128 0x1d
	.long	0x290
	.uleb128 0x2
	.byte	0x91
	.sleb128 0
	.uleb128 0x1d
	.long	0x29b
	.uleb128 0x2
	.byte	0x91
	.sleb128 4
	.uleb128 0x19
	.long	.LBB147
	.long	.LBE147-.LBB147
	.uleb128 0x23
	.long	0x2a7
	.long	.LLST27
	.uleb128 0x27
	.long	.LVL36
	.long	0x267
	.byte	0
	.byte	0
	.uleb128 0x18
	.long	0x1f8
	.long	.LFB16
	.long	.LFE16-.LFB16
	.uleb128 0x1
	.byte	0x9c
	.long	0x68a
	.uleb128 0x1b
	.long	.LASF49
	.byte	0x1
	.byte	0x6d
	.long	0x27b
	.uleb128 0x2
	.byte	0x91
	.sleb128 0
	.uleb128 0x24
	.long	0x286
	.long	.LBB148
	.long	.LBE148-.LBB148
	.byte	0x1
	.byte	0x6f
	.long	0x680
	.uleb128 0x21
	.long	0x29b
	.long	.LLST28
	.uleb128 0x21
	.long	0x290
	.long	.LLST29
	.uleb128 0x19
	.long	.LBB149
	.long	.LBE149-.LBB149
	.uleb128 0x23
	.long	0x2a7
	.long	.LLST30
	.uleb128 0x27
	.long	.LVL42
	.long	0x267
	.byte	0
	.byte	0
	.uleb128 0x27
	.long	.LVL38
	.long	0x701
	.byte	0
	.uleb128 0x28
	.long	.LASF51
	.byte	0x5
	.byte	0x34
	.long	0x262
	.byte	0x50
	.uleb128 0x28
	.long	.LASF52
	.byte	0x5
	.byte	0x35
	.long	0x262
	.byte	0x19
	.uleb128 0x29
	.long	.LASF53
	.byte	0x5
	.byte	0x37
	.long	0x6b8
	.sleb128 -2146729984
	.uleb128 0x16
	.byte	0x4
	.long	0x71
	.uleb128 0x15
	.long	0x6b2
	.uleb128 0x2a
	.long	.LASF54
	.byte	0x1
	.byte	0x21
	.long	0x2c
	.uleb128 0x5
	.byte	0x3
	.long	terminal_row
	.uleb128 0x2a
	.long	.LASF55
	.byte	0x1
	.byte	0x22
	.long	0x2c
	.uleb128 0x5
	.byte	0x3
	.long	terminal_column
	.uleb128 0x2a
	.long	.LASF56
	.byte	0x1
	.byte	0x23
	.long	0x5f
	.uleb128 0x5
	.byte	0x3
	.long	terminal_color
	.uleb128 0x2a
	.long	.LASF57
	.byte	0x1
	.byte	0x24
	.long	0x6b2
	.uleb128 0x5
	.byte	0x3
	.long	terminal_buffer
	.uleb128 0x2b
	.long	.LASF68
	.long	.LASF68
	.byte	0x7
	.byte	0x1e
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
	.uleb128 0x3b
	.byte	0
	.uleb128 0x3
	.uleb128 0xe
	.byte	0
	.byte	0
	.uleb128 0x5
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
	.uleb128 0x6
	.uleb128 0x4
	.byte	0x1
	.uleb128 0x3
	.uleb128 0xe
	.uleb128 0xb
	.uleb128 0xb
	.uleb128 0x49
	.uleb128 0x13
	.uleb128 0x3a
	.uleb128 0xb
	.uleb128 0x3b
	.uleb128 0xb
	.uleb128 0x1
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0x7
	.uleb128 0x28
	.byte	0
	.uleb128 0x3
	.uleb128 0xe
	.uleb128 0x1c
	.uleb128 0xb
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
	.uleb128 0xc
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
	.uleb128 0xd
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
	.uleb128 0xe
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
	.uleb128 0xf
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
	.uleb128 0x5
	.byte	0
	.uleb128 0x49
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0x12
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
	.uleb128 0x13
	.uleb128 0x2e
	.byte	0x1
	.uleb128 0x47
	.uleb128 0x13
	.uleb128 0x20
	.uleb128 0xb
	.uleb128 0x1
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
	.uleb128 0x20
	.uleb128 0xb
	.uleb128 0x1
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0x15
	.uleb128 0x26
	.byte	0
	.uleb128 0x49
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0x16
	.uleb128 0xf
	.byte	0
	.uleb128 0xb
	.uleb128 0xb
	.uleb128 0x49
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0x17
	.uleb128 0xb
	.byte	0x1
	.byte	0
	.byte	0
	.uleb128 0x18
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
	.uleb128 0x19
	.uleb128 0xb
	.byte	0x1
	.uleb128 0x11
	.uleb128 0x1
	.uleb128 0x12
	.uleb128 0x6
	.byte	0
	.byte	0
	.uleb128 0x1a
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
	.uleb128 0x1b
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
	.uleb128 0x1c
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
	.uleb128 0x1d
	.uleb128 0x5
	.byte	0
	.uleb128 0x31
	.uleb128 0x13
	.uleb128 0x2
	.uleb128 0x18
	.byte	0
	.byte	0
	.uleb128 0x1e
	.uleb128 0x34
	.byte	0
	.uleb128 0x31
	.uleb128 0x13
	.uleb128 0x2
	.uleb128 0x18
	.byte	0
	.byte	0
	.uleb128 0x1f
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
	.uleb128 0x20
	.uleb128 0x1d
	.byte	0x1
	.uleb128 0x31
	.uleb128 0x13
	.uleb128 0x52
	.uleb128 0x1
	.uleb128 0x55
	.uleb128 0x17
	.uleb128 0x58
	.uleb128 0xb
	.uleb128 0x59
	.uleb128 0xb
	.uleb128 0x1
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0x21
	.uleb128 0x5
	.byte	0
	.uleb128 0x31
	.uleb128 0x13
	.uleb128 0x2
	.uleb128 0x17
	.byte	0
	.byte	0
	.uleb128 0x22
	.uleb128 0xb
	.byte	0x1
	.uleb128 0x55
	.uleb128 0x17
	.byte	0
	.byte	0
	.uleb128 0x23
	.uleb128 0x34
	.byte	0
	.uleb128 0x31
	.uleb128 0x13
	.uleb128 0x2
	.uleb128 0x17
	.byte	0
	.byte	0
	.uleb128 0x24
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
	.uleb128 0x25
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
	.uleb128 0x26
	.uleb128 0xb
	.byte	0x1
	.uleb128 0x55
	.uleb128 0x17
	.uleb128 0x1
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0x27
	.uleb128 0x4109
	.byte	0
	.uleb128 0x11
	.uleb128 0x1
	.uleb128 0x31
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0x28
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
	.uleb128 0x1c
	.uleb128 0xb
	.byte	0
	.byte	0
	.uleb128 0x29
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
	.uleb128 0x1c
	.uleb128 0xd
	.byte	0
	.byte	0
	.uleb128 0x2a
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
	.uleb128 0x2b
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
	.byte	0
	.section	.debug_loc,"",@progbits
.Ldebug_loc0:
.LLST0:
	.long	.LVL0-.Ltext0
	.long	.LVL1-.Ltext0
	.value	0x2
	.byte	0x30
	.byte	0x9f
	.long	0
	.long	0
.LLST1:
	.long	.LVL7-.Ltext0
	.long	.LVL8-.Ltext0
	.value	0x2
	.byte	0x30
	.byte	0x9f
	.long	0
	.long	0
.LLST2:
	.long	.LVL8-.Ltext0
	.long	.LVL9-.Ltext0
	.value	0x2
	.byte	0x30
	.byte	0x9f
	.long	0
	.long	0
.LLST3:
	.long	.LVL11-.Ltext0
	.long	.LVL15-.Ltext0
	.value	0x1
	.byte	0x51
	.long	0
	.long	0
.LLST4:
	.long	.LVL11-.Ltext0
	.long	.LVL14-.Ltext0
	.value	0x1
	.byte	0x50
	.long	.LVL14-.Ltext0
	.long	.LVL15-.Ltext0
	.value	0x5
	.byte	0x3
	.long	terminal_column
	.long	0
	.long	0
.LLST5:
	.long	.LVL11-.Ltext0
	.long	.LVL15-.Ltext0
	.value	0x5
	.byte	0x3
	.long	terminal_color
	.long	0
	.long	0
.LLST6:
	.long	.LVL11-.Ltext0
	.long	.LVL15-.Ltext0
	.value	0x1
	.byte	0x57
	.long	0
	.long	0
.LLST7:
	.long	.LVL11-.Ltext0
	.long	.LVL14-.Ltext0
	.value	0x9
	.byte	0x71
	.sleb128 0
	.byte	0x8
	.byte	0x50
	.byte	0x1e
	.byte	0x70
	.sleb128 0
	.byte	0x22
	.byte	0x9f
	.long	.LVL14-.Ltext0
	.long	.LVL15-.Ltext0
	.value	0xd
	.byte	0x71
	.sleb128 0
	.byte	0x8
	.byte	0x50
	.byte	0x1e
	.byte	0x3
	.long	terminal_column
	.byte	0x6
	.byte	0x22
	.byte	0x9f
	.long	0
	.long	0
.LLST8:
	.long	.LVL16-.Ltext0
	.long	.LVL21-.Ltext0
	.value	0x1
	.byte	0x51
	.long	0
	.long	0
.LLST9:
	.long	.LVL16-.Ltext0
	.long	.LVL17-.Ltext0
	.value	0x2
	.byte	0x3f
	.byte	0x9f
	.long	0
	.long	0
.LLST10:
	.long	.LVL16-.Ltext0
	.long	.LVL17-.Ltext0
	.value	0x4
	.byte	0xa
	.value	0x3d4
	.byte	0x9f
	.long	0
	.long	0
.LLST11:
	.long	.LVL17-.Ltext0
	.long	.LVL18-.Ltext0
	.value	0x1
	.byte	0x51
	.long	0
	.long	0
.LLST12:
	.long	.LVL17-.Ltext0
	.long	.LVL18-.Ltext0
	.value	0x4
	.byte	0xa
	.value	0x3d5
	.byte	0x9f
	.long	0
	.long	0
.LLST13:
	.long	.LVL18-.Ltext0
	.long	.LVL19-.Ltext0
	.value	0x2
	.byte	0x3e
	.byte	0x9f
	.long	0
	.long	0
.LLST14:
	.long	.LVL18-.Ltext0
	.long	.LVL19-.Ltext0
	.value	0x4
	.byte	0xa
	.value	0x3d4
	.byte	0x9f
	.long	0
	.long	0
.LLST15:
	.long	.LVL19-.Ltext0
	.long	.LVL20-.Ltext0
	.value	0x5
	.byte	0x71
	.sleb128 0
	.byte	0x38
	.byte	0x25
	.byte	0x9f
	.long	0
	.long	0
.LLST16:
	.long	.LVL19-.Ltext0
	.long	.LVL20-.Ltext0
	.value	0x4
	.byte	0xa
	.value	0x3d5
	.byte	0x9f
	.long	0
	.long	0
.LLST17:
	.long	.LVL21-.Ltext0
	.long	.LVL23-.Ltext0
	.value	0x2
	.byte	0x3a
	.byte	0x9f
	.long	.LVL25-.Ltext0
	.long	.LFE13-.Ltext0
	.value	0x2
	.byte	0x3a
	.byte	0x9f
	.long	0
	.long	0
.LLST18:
	.long	.LVL22-.Ltext0
	.long	.LVL23-.Ltext0
	.value	0x1
	.byte	0x51
	.long	0
	.long	0
.LLST19:
	.long	.LVL27-.Ltext0
	.long	.LVL28-.Ltext0
	.value	0x2
	.byte	0x3f
	.byte	0x9f
	.long	0
	.long	0
.LLST20:
	.long	.LVL27-.Ltext0
	.long	.LVL28-.Ltext0
	.value	0x4
	.byte	0xa
	.value	0x3d4
	.byte	0x9f
	.long	0
	.long	0
.LLST21:
	.long	.LVL28-.Ltext0
	.long	.LVL29-.Ltext0
	.value	0x1
	.byte	0x51
	.long	0
	.long	0
.LLST22:
	.long	.LVL28-.Ltext0
	.long	.LVL29-.Ltext0
	.value	0x4
	.byte	0xa
	.value	0x3d5
	.byte	0x9f
	.long	0
	.long	0
.LLST23:
	.long	.LVL29-.Ltext0
	.long	.LVL30-.Ltext0
	.value	0x2
	.byte	0x3e
	.byte	0x9f
	.long	0
	.long	0
.LLST24:
	.long	.LVL29-.Ltext0
	.long	.LVL30-.Ltext0
	.value	0x4
	.byte	0xa
	.value	0x3d4
	.byte	0x9f
	.long	0
	.long	0
.LLST25:
	.long	.LVL30-.Ltext0
	.long	.LVL31-.Ltext0
	.value	0x5
	.byte	0x71
	.sleb128 0
	.byte	0x38
	.byte	0x25
	.byte	0x9f
	.long	0
	.long	0
.LLST26:
	.long	.LVL30-.Ltext0
	.long	.LVL31-.Ltext0
	.value	0x4
	.byte	0xa
	.value	0x3d5
	.byte	0x9f
	.long	0
	.long	0
.LLST27:
	.long	.LVL33-.Ltext0
	.long	.LVL34-.Ltext0
	.value	0x2
	.byte	0x30
	.byte	0x9f
	.long	.LVL34-.Ltext0
	.long	.LVL35-.Ltext0
	.value	0x7
	.byte	0x73
	.sleb128 0
	.byte	0x91
	.sleb128 0
	.byte	0x6
	.byte	0x1c
	.byte	0x9f
	.long	.LVL35-.Ltext0
	.long	.LVL36-.Ltext0
	.value	0x8
	.byte	0x91
	.sleb128 0
	.byte	0x6
	.byte	0x20
	.byte	0x73
	.sleb128 0
	.byte	0x22
	.byte	0x9f
	.long	0
	.long	0
.LLST28:
	.long	.LVL39-.Ltext0
	.long	.LVL40-.Ltext0
	.value	0x1
	.byte	0x50
	.long	0
	.long	0
.LLST29:
	.long	.LVL39-.Ltext0
	.long	.LVL40-.Ltext0
	.value	0x1
	.byte	0x53
	.long	.LVL40-.Ltext0
	.long	.LFE16-.Ltext0
	.value	0x2
	.byte	0x91
	.sleb128 0
	.long	0
	.long	0
.LLST30:
	.long	.LVL39-.Ltext0
	.long	.LVL40-.Ltext0
	.value	0x2
	.byte	0x30
	.byte	0x9f
	.long	.LVL40-.Ltext0
	.long	.LVL41-.Ltext0
	.value	0x7
	.byte	0x73
	.sleb128 0
	.byte	0x91
	.sleb128 0
	.byte	0x6
	.byte	0x1c
	.byte	0x9f
	.long	.LVL41-.Ltext0
	.long	.LVL42-.Ltext0
	.value	0x8
	.byte	0x91
	.sleb128 0
	.byte	0x6
	.byte	0x20
	.byte	0x73
	.sleb128 0
	.byte	0x22
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
	.long	.LBB115-.Ltext0
	.long	.LBE115-.Ltext0
	.long	.LBB119-.Ltext0
	.long	.LBE119-.Ltext0
	.long	.LBB120-.Ltext0
	.long	.LBE120-.Ltext0
	.long	0
	.long	0
	.long	.LBB131-.Ltext0
	.long	.LBE131-.Ltext0
	.long	.LBB136-.Ltext0
	.long	.LBE136-.Ltext0
	.long	0
	.long	0
	.long	.LBB137-.Ltext0
	.long	.LBE137-.Ltext0
	.long	.LBB140-.Ltext0
	.long	.LBE140-.Ltext0
	.long	0
	.long	0
	.section	.debug_line,"",@progbits
.Ldebug_line0:
	.section	.debug_str,"MS",@progbits,1
.LASF24:
	.string	"COLOR_LIGHT_CYAN"
.LASF61:
	.string	"decltype(nullptr)"
.LASF41:
	.string	"_ZN3TTY12UpdateCursorEv"
.LASF28:
	.string	"COLOR_WHITE"
.LASF43:
	.string	"SetColor"
.LASF48:
	.string	"index"
.LASF5:
	.string	"short int"
.LASF6:
	.string	"size_t"
.LASF31:
	.string	"color"
.LASF60:
	.string	"/home/pfalcato/Spartix/kernel"
.LASF13:
	.string	"COLOR_BLACK"
.LASF38:
	.string	"_ZN3TTY5WriteEPKcm"
.LASF53:
	.string	"VGA_MEMORY"
.LASF49:
	.string	"data"
.LASF52:
	.string	"VGA_HEIGHT"
.LASF51:
	.string	"VGA_WIDTH"
.LASF58:
	.string	"GNU C++11 5.3.0 -mtune=generic -march=pentiumpro -g -O2 -std=c++11 -ffreestanding -fbuiltin -fstack-protector-strong -fno-exceptions -fno-rtti"
.LASF25:
	.string	"COLOR_LIGHT_RED"
.LASF55:
	.string	"terminal_column"
.LASF7:
	.string	"uint8_t"
.LASF22:
	.string	"COLOR_LIGHT_BLUE"
.LASF63:
	.string	"outb"
.LASF36:
	.string	"Write"
.LASF2:
	.string	"long long int"
.LASF42:
	.string	"_ZN3TTY4InitEv"
.LASF65:
	.string	"_ZN3TTY11WriteStringEPKc"
.LASF40:
	.string	"Init"
.LASF0:
	.string	"long int"
.LASF30:
	.string	"make_vgaentry"
.LASF57:
	.string	"terminal_buffer"
.LASF67:
	.string	"_Z15terminal_scrollv"
.LASF19:
	.string	"COLOR_BROWN"
.LASF47:
	.string	"_Z19terminal_putentryatchmm"
.LASF37:
	.string	"_ZN3TTY7PutCharEc"
.LASF59:
	.string	"arch/i386/tty.cpp"
.LASF3:
	.string	"long double"
.LASF35:
	.string	"PutChar"
.LASF8:
	.string	"unsigned char"
.LASF29:
	.string	"make_color"
.LASF14:
	.string	"COLOR_BLUE"
.LASF15:
	.string	"COLOR_GREEN"
.LASF4:
	.string	"signed char"
.LASF11:
	.string	"long long unsigned int"
.LASF44:
	.string	"_ZN3TTY8SetColorEh"
.LASF12:
	.string	"unsigned int"
.LASF9:
	.string	"uint16_t"
.LASF26:
	.string	"COLOR_LIGHT_MAGENTA"
.LASF39:
	.string	"UpdateCursor"
.LASF10:
	.string	"short unsigned int"
.LASF33:
	.string	"char"
.LASF68:
	.string	"strlen"
.LASF27:
	.string	"COLOR_LIGHT_BROWN"
.LASF54:
	.string	"terminal_row"
.LASF32:
	.string	"color16"
.LASF46:
	.string	"terminal_putentryat"
.LASF34:
	.string	"port"
.LASF64:
	.string	"WriteString"
.LASF1:
	.string	"long unsigned int"
.LASF23:
	.string	"COLOR_LIGHT_GREEN"
.LASF50:
	.string	"size"
.LASF62:
	.string	"vga_color"
.LASF21:
	.string	"COLOR_DARK_GREY"
.LASF66:
	.string	"terminal_scroll"
.LASF45:
	.string	"position"
.LASF17:
	.string	"COLOR_RED"
.LASF16:
	.string	"COLOR_CYAN"
.LASF20:
	.string	"COLOR_LIGHT_GREY"
.LASF56:
	.string	"terminal_color"
.LASF18:
	.string	"COLOR_MAGENTA"
	.ident	"GCC: (GNU) 5.3.0"
