	.file	"gdt.cpp"
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
	.globl	_Z8init_gdtv
	.type	_Z8init_gdtv, @function
_Z8init_gdtv:
.LFB0:
	.file 1 "arch/i386/gdt.cpp"
	.loc 1 22 0
	.cfi_startproc
	pushl	%edi
	.cfi_def_cfa_offset 8
	.cfi_offset 7, -8
	.loc 1 23 0
	movl	$_ZL7entries, %edx
	.loc 1 22 0
	pushl	%ebx
	.cfi_def_cfa_offset 12
	.cfi_offset 3, -12
	.loc 1 23 0
	xorl	%eax, %eax
	movl	%edx, %edi
.LBB30:
.LBB31:
	.loc 1 41 0
	movl	$-1, %ebx
.LBE31:
.LBE30:
	.loc 1 23 0
	movl	$12, %ecx
	.loc 1 22 0
	subl	$16, %esp
	.cfi_def_cfa_offset 28
.LBB34:
.LBB35:
	.loc 1 41 0
	movl	$-1, %edx
.LBE35:
.LBE34:
	.loc 1 23 0
	rep stosl
.LVL0:
.LBB38:
.LBB39:
	.loc 1 41 0
	movl	$-1, %ecx
.LBE39:
.LBE38:
.LBB42:
.LBB32:
	movw	%bx, _ZL7entries+24
.LBE32:
.LBE42:
.LBB43:
.LBB44:
	.loc 1 50 0
	movl	$_ZL9tss_entry, %ebx
.LBE44:
.LBE43:
.LBB67:
.LBB40:
	.loc 1 41 0
	movw	%cx, _ZL7entries+16
.LBE40:
.LBE67:
.LBB68:
.LBB61:
.LBB45:
.LBB46:
	.loc 1 38 0
	movl	%ebx, %ecx
.LBE46:
.LBE45:
.LBE61:
.LBE68:
.LBB69:
.LBB36:
	.loc 1 41 0
	movw	%dx, _ZL7entries+8
.LBE36:
.LBE69:
.LBB70:
.LBB62:
.LBB54:
.LBB47:
	.loc 1 38 0
	shrl	$16, %ecx
.LBE47:
.LBE54:
.LBE62:
.LBE70:
.LBB71:
.LBB72:
	.loc 1 41 0
	movl	$-1, %edi
.LBE72:
.LBE71:
.LBB75:
.LBB63:
	.loc 1 51 0
	movl	$_ZL9tss_entry+104, %edx
.LBB55:
.LBB48:
	.loc 1 38 0
	movb	%cl, _ZL7entries+44
	.loc 1 39 0
	movl	%ebx, %ecx
.LBE48:
.LBE55:
.LBE63:
.LBE75:
.LBB76:
.LBB73:
	.loc 1 41 0
	movw	%di, _ZL7entries+32
.LBE73:
.LBE76:
.LBB77:
.LBB64:
.LBB56:
.LBB49:
	.loc 1 39 0
	shrl	$24, %ecx
	.loc 1 41 0
	movw	%dx, _ZL7entries+40
.LBE49:
.LBE56:
	.loc 1 54 0
	movl	%ebx, %edi
.LBB57:
.LBB50:
	.loc 1 39 0
	movb	%cl, _ZL7entries+47
	.loc 1 42 0
	shrl	$16, %edx
.LBE50:
.LBE57:
	.loc 1 54 0
	movl	$26, %ecx
	rep stosl
.LBB58:
.LBB51:
	.loc 1 42 0
	andl	$15, %edx
.LBE51:
.LBE58:
.LBE64:
.LBE77:
.LBB78:
.LBB79:
	.loc 1 62 0
	movl	$47, %eax
.LBE79:
.LBE78:
.LBB83:
.LBB65:
.LBB59:
.LBB52:
	.loc 1 37 0
	movw	%bx, _ZL7entries+42
	.loc 1 42 0
	movb	%dl, _ZL7entries+46
.LBE52:
.LBE59:
.LBE65:
.LBE83:
.LBB84:
.LBB80:
	.loc 1 62 0
	movw	%ax, _ZL7gdt_ptr
.LBE80:
.LBE84:
.LBB85:
.LBB37:
	.loc 1 43 0
	movb	$-49, _ZL7entries+14
	.loc 1 44 0
	movb	$-102, _ZL7entries+13
.LVL1:
.LBE37:
.LBE85:
.LBB86:
.LBB41:
	.loc 1 43 0
	movb	$-49, _ZL7entries+22
	.loc 1 44 0
	movb	$-110, _ZL7entries+21
.LVL2:
.LBE41:
.LBE86:
.LBB87:
.LBB33:
	.loc 1 43 0
	movb	$-49, _ZL7entries+30
	.loc 1 44 0
	movb	$-6, _ZL7entries+29
.LVL3:
.LBE33:
.LBE87:
.LBB88:
.LBB74:
	.loc 1 43 0
	movb	$-49, _ZL7entries+38
	.loc 1 44 0
	movb	$-14, _ZL7entries+37
.LVL4:
.LBE74:
.LBE88:
.LBB89:
.LBB66:
.LBB60:
.LBB53:
	movb	$-23, _ZL7entries+45
.LVL5:
.LBE53:
.LBE60:
	.loc 1 55 0
	movl	$16, _ZL9tss_entry+8
	.loc 1 56 0
	movl	$-1069547776, _ZL9tss_entry+4
	.loc 1 57 0
	movl	$11, _ZL9tss_entry+76
	.loc 1 58 0
	movl	$19, _ZL9tss_entry+92
	movl	$19, _ZL9tss_entry+88
	movl	$19, _ZL9tss_entry+72
	movl	$19, _ZL9tss_entry+84
	movl	$19, _ZL9tss_entry+80
.LVL6:
.LBE66:
.LBE89:
.LBB90:
.LBB81:
	.loc 1 63 0
	movl	$_ZL7entries, _ZL7gdt_ptr+2
	.loc 1 64 0
	pushl	$_ZL7gdt_ptr
	.cfi_def_cfa_offset 32
	call	GDT_Flush
.LVL7:
.LBE81:
.LBE90:
	.loc 1 33 0
	addl	$20, %esp
	.cfi_def_cfa_offset 12
	popl	%ebx
	.cfi_restore 3
	.cfi_def_cfa_offset 8
	popl	%edi
	.cfi_restore 7
	.cfi_def_cfa_offset 4
.LBB91:
.LBB82:
	.loc 1 65 0
	jmp	tss_flush
.LVL8:
.LBE82:
.LBE91:
	.cfi_endproc
.LFE0:
	.size	_Z8init_gdtv, .-_Z8init_gdtv
	.section	.text.unlikely
.LCOLDE0:
	.text
.LHOTE0:
	.section	.text.unlikely
.LCOLDB1:
	.text
.LHOTB1:
	.align 16
	.globl	_Z17create_descriptormmmhh
	.type	_Z17create_descriptormmmhh, @function
_Z17create_descriptormmmhh:
.LFB1:
	.loc 1 36 0
	.cfi_startproc
.LVL9:
	pushl	%ebx
	.cfi_def_cfa_offset 8
	.cfi_offset 3, -8
	.loc 1 36 0
	movl	8(%esp), %eax
	movl	12(%esp), %ecx
	movl	16(%esp), %edx
	.loc 1 38 0
	movl	%ecx, %ebx
	.loc 1 37 0
	movw	%cx, _ZL7entries+2(,%eax,8)
	.loc 1 39 0
	shrl	$24, %ecx
	movb	%cl, _ZL7entries+7(,%eax,8)
	.loc 1 43 0
	movzbl	24(%esp), %ecx
	.loc 1 38 0
	shrl	$16, %ebx
	.loc 1 41 0
	movw	%dx, _ZL7entries(,%eax,8)
	.loc 1 43 0
	shrl	$16, %edx
	.loc 1 38 0
	movb	%bl, _ZL7entries+4(,%eax,8)
	.loc 1 43 0
	andl	$15, %edx
	andl	$-16, %ecx
	orl	%ecx, %edx
	movb	%dl, _ZL7entries+6(,%eax,8)
	.loc 1 44 0
	movl	20(%esp), %edx
	.loc 1 46 0
	popl	%ebx
	.cfi_restore 3
	.cfi_def_cfa_offset 4
	.loc 1 44 0
	movb	%dl, _ZL7entries+5(,%eax,8)
	.loc 1 46 0
	ret
	.cfi_endproc
.LFE1:
	.size	_Z17create_descriptormmmhh, .-_Z17create_descriptormmmhh
	.section	.text.unlikely
.LCOLDE1:
	.text
.LHOTE1:
	.section	.text.unlikely
.LCOLDB2:
	.text
.LHOTB2:
	.align 16
	.globl	_Z8load_gdtv
	.type	_Z8load_gdtv, @function
_Z8load_gdtv:
.LFB3:
	.loc 1 61 0
	.cfi_startproc
	subl	$24, %esp
	.cfi_def_cfa_offset 28
	.loc 1 62 0
	movl	$47, %eax
	.loc 1 63 0
	movl	$_ZL7entries, _ZL7gdt_ptr+2
	.loc 1 64 0
	pushl	$_ZL7gdt_ptr
	.cfi_def_cfa_offset 32
	.loc 1 62 0
	movw	%ax, _ZL7gdt_ptr
	.loc 1 64 0
	call	GDT_Flush
.LVL10:
	.loc 1 66 0
	addl	$28, %esp
	.cfi_def_cfa_offset 4
	.loc 1 65 0
	jmp	tss_flush
.LVL11:
	.cfi_endproc
.LFE3:
	.size	_Z8load_gdtv, .-_Z8load_gdtv
	.section	.text.unlikely
.LCOLDE2:
	.text
.LHOTE2:
	.local	_ZL9tss_entry
	.comm	_ZL9tss_entry,104,32
	.local	_ZL7entries
	.comm	_ZL7entries,48,32
	.local	_ZL7gdt_ptr
	.comm	_ZL7gdt_ptr,6,4
.Letext0:
	.section	.text.unlikely
.Letext_cold0:
	.file 2 "/home/pfalcato/i686-elf/lib/gcc/i686-elf/5.3.0/include/stdint-gcc.h"
	.file 3 "include/kernel/gdt.h"
	.section	.debug_info,"",@progbits
.Ldebug_info0:
	.long	0x55a
	.value	0x4
	.long	.Ldebug_abbrev0
	.byte	0x4
	.uleb128 0x1
	.long	.LASF41
	.byte	0x4
	.long	.LASF42
	.long	.LASF43
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
	.byte	0x2
	.byte	0x2e
	.long	0x4c
	.uleb128 0x2
	.byte	0x1
	.byte	0x8
	.long	.LASF4
	.uleb128 0x3
	.long	.LASF6
	.byte	0x2
	.byte	0x31
	.long	0x5e
	.uleb128 0x2
	.byte	0x2
	.byte	0x7
	.long	.LASF7
	.uleb128 0x3
	.long	.LASF8
	.byte	0x2
	.byte	0x34
	.long	0x70
	.uleb128 0x2
	.byte	0x4
	.byte	0x7
	.long	.LASF9
	.uleb128 0x2
	.byte	0x8
	.byte	0x7
	.long	.LASF10
	.uleb128 0x4
	.byte	0x4
	.byte	0x5
	.string	"int"
	.uleb128 0x2
	.byte	0x4
	.byte	0x7
	.long	.LASF11
	.uleb128 0x5
	.long	.LASF14
	.byte	0x6
	.byte	0x3
	.byte	0x12
	.long	0xb1
	.uleb128 0x6
	.long	.LASF12
	.byte	0x3
	.byte	0x14
	.long	0x53
	.byte	0
	.uleb128 0x6
	.long	.LASF13
	.byte	0x3
	.byte	0x15
	.long	0x65
	.byte	0x2
	.byte	0
	.uleb128 0x5
	.long	.LASF15
	.byte	0x8
	.byte	0x3
	.byte	0x18
	.long	0x106
	.uleb128 0x6
	.long	.LASF16
	.byte	0x3
	.byte	0x1a
	.long	0x53
	.byte	0
	.uleb128 0x6
	.long	.LASF17
	.byte	0x3
	.byte	0x1b
	.long	0x53
	.byte	0x2
	.uleb128 0x6
	.long	.LASF18
	.byte	0x3
	.byte	0x1c
	.long	0x41
	.byte	0x4
	.uleb128 0x6
	.long	.LASF19
	.byte	0x3
	.byte	0x1d
	.long	0x41
	.byte	0x5
	.uleb128 0x6
	.long	.LASF20
	.byte	0x3
	.byte	0x1e
	.long	0x41
	.byte	0x6
	.uleb128 0x6
	.long	.LASF21
	.byte	0x3
	.byte	0x1f
	.long	0x41
	.byte	0x7
	.byte	0
	.uleb128 0x3
	.long	.LASF22
	.byte	0x3
	.byte	0x22
	.long	0x8c
	.uleb128 0x5
	.long	.LASF23
	.byte	0x68
	.byte	0x3
	.byte	0x24
	.long	0x25c
	.uleb128 0x6
	.long	.LASF24
	.byte	0x3
	.byte	0x26
	.long	0x65
	.byte	0
	.uleb128 0x6
	.long	.LASF25
	.byte	0x3
	.byte	0x27
	.long	0x65
	.byte	0x4
	.uleb128 0x7
	.string	"ss0"
	.byte	0x3
	.byte	0x28
	.long	0x65
	.byte	0x8
	.uleb128 0x6
	.long	.LASF26
	.byte	0x3
	.byte	0x29
	.long	0x65
	.byte	0xc
	.uleb128 0x7
	.string	"ss1"
	.byte	0x3
	.byte	0x2a
	.long	0x65
	.byte	0x10
	.uleb128 0x6
	.long	.LASF27
	.byte	0x3
	.byte	0x2b
	.long	0x65
	.byte	0x14
	.uleb128 0x7
	.string	"ss2"
	.byte	0x3
	.byte	0x2c
	.long	0x65
	.byte	0x18
	.uleb128 0x7
	.string	"cr3"
	.byte	0x3
	.byte	0x2d
	.long	0x65
	.byte	0x1c
	.uleb128 0x7
	.string	"eip"
	.byte	0x3
	.byte	0x2e
	.long	0x65
	.byte	0x20
	.uleb128 0x6
	.long	.LASF28
	.byte	0x3
	.byte	0x2f
	.long	0x65
	.byte	0x24
	.uleb128 0x7
	.string	"eax"
	.byte	0x3
	.byte	0x30
	.long	0x65
	.byte	0x28
	.uleb128 0x7
	.string	"ecx"
	.byte	0x3
	.byte	0x31
	.long	0x65
	.byte	0x2c
	.uleb128 0x7
	.string	"edx"
	.byte	0x3
	.byte	0x32
	.long	0x65
	.byte	0x30
	.uleb128 0x7
	.string	"ebx"
	.byte	0x3
	.byte	0x33
	.long	0x65
	.byte	0x34
	.uleb128 0x7
	.string	"esp"
	.byte	0x3
	.byte	0x34
	.long	0x65
	.byte	0x38
	.uleb128 0x7
	.string	"ebp"
	.byte	0x3
	.byte	0x35
	.long	0x65
	.byte	0x3c
	.uleb128 0x7
	.string	"esi"
	.byte	0x3
	.byte	0x36
	.long	0x65
	.byte	0x40
	.uleb128 0x7
	.string	"edi"
	.byte	0x3
	.byte	0x37
	.long	0x65
	.byte	0x44
	.uleb128 0x7
	.string	"es"
	.byte	0x3
	.byte	0x38
	.long	0x65
	.byte	0x48
	.uleb128 0x7
	.string	"cs"
	.byte	0x3
	.byte	0x39
	.long	0x65
	.byte	0x4c
	.uleb128 0x7
	.string	"ss"
	.byte	0x3
	.byte	0x3a
	.long	0x65
	.byte	0x50
	.uleb128 0x7
	.string	"ds"
	.byte	0x3
	.byte	0x3b
	.long	0x65
	.byte	0x54
	.uleb128 0x7
	.string	"fs"
	.byte	0x3
	.byte	0x3c
	.long	0x65
	.byte	0x58
	.uleb128 0x7
	.string	"gs"
	.byte	0x3
	.byte	0x3d
	.long	0x65
	.byte	0x5c
	.uleb128 0x7
	.string	"ldt"
	.byte	0x3
	.byte	0x3e
	.long	0x65
	.byte	0x60
	.uleb128 0x6
	.long	.LASF29
	.byte	0x3
	.byte	0x3f
	.long	0x53
	.byte	0x64
	.uleb128 0x6
	.long	.LASF30
	.byte	0x3
	.byte	0x40
	.long	0x53
	.byte	0x66
	.byte	0
	.uleb128 0x3
	.long	.LASF31
	.byte	0x3
	.byte	0x43
	.long	0x111
	.uleb128 0x2
	.byte	0xc
	.byte	0x4
	.long	.LASF32
	.uleb128 0x8
	.long	.LASF44
	.uleb128 0x9
	.long	.LASF45
	.byte	0x1
	.byte	0x23
	.long	.LASF34
	.byte	0x1
	.long	0x2bb
	.uleb128 0xa
	.long	.LASF33
	.byte	0x1
	.byte	0x23
	.long	0x65
	.uleb128 0xa
	.long	.LASF13
	.byte	0x1
	.byte	0x23
	.long	0x65
	.uleb128 0xa
	.long	.LASF12
	.byte	0x1
	.byte	0x23
	.long	0x65
	.uleb128 0xa
	.long	.LASF19
	.byte	0x1
	.byte	0x23
	.long	0x41
	.uleb128 0xa
	.long	.LASF20
	.byte	0x1
	.byte	0x23
	.long	0x41
	.byte	0
	.uleb128 0xb
	.long	.LASF46
	.byte	0x1
	.byte	0x3c
	.long	.LASF35
	.byte	0x1
	.uleb128 0xc
	.long	.LASF47
	.byte	0x1
	.byte	0x30
	.byte	0x1
	.long	0x2ea
	.uleb128 0xd
	.long	.LASF13
	.byte	0x1
	.byte	0x32
	.long	0x65
	.uleb128 0xd
	.long	.LASF12
	.byte	0x1
	.byte	0x33
	.long	0x65
	.byte	0
	.uleb128 0xe
	.long	.LASF48
	.byte	0x1
	.byte	0x15
	.long	.LASF49
	.long	.LFB0
	.long	.LFE0-.LFB0
	.uleb128 0x1
	.byte	0x9c
	.long	0x493
	.uleb128 0xf
	.long	0x273
	.long	.LBB30
	.long	.Ldebug_ranges0+0
	.byte	0x1
	.byte	0x1d
	.long	0x344
	.uleb128 0x10
	.long	0x2af
	.long	.LLST0
	.uleb128 0x10
	.long	0x2a4
	.long	.LLST1
	.uleb128 0x10
	.long	0x299
	.long	.LLST2
	.uleb128 0x10
	.long	0x28e
	.long	.LLST3
	.uleb128 0x10
	.long	0x283
	.long	.LLST4
	.byte	0
	.uleb128 0xf
	.long	0x273
	.long	.LBB34
	.long	.Ldebug_ranges0+0x20
	.byte	0x1
	.byte	0x1b
	.long	0x385
	.uleb128 0x10
	.long	0x2af
	.long	.LLST5
	.uleb128 0x10
	.long	0x2a4
	.long	.LLST6
	.uleb128 0x10
	.long	0x299
	.long	.LLST7
	.uleb128 0x10
	.long	0x28e
	.long	.LLST8
	.uleb128 0x10
	.long	0x283
	.long	.LLST9
	.byte	0
	.uleb128 0xf
	.long	0x273
	.long	.LBB38
	.long	.Ldebug_ranges0+0x40
	.byte	0x1
	.byte	0x1c
	.long	0x3c6
	.uleb128 0x10
	.long	0x2af
	.long	.LLST10
	.uleb128 0x10
	.long	0x2a4
	.long	.LLST11
	.uleb128 0x10
	.long	0x299
	.long	.LLST12
	.uleb128 0x10
	.long	0x28e
	.long	.LLST13
	.uleb128 0x10
	.long	0x283
	.long	.LLST14
	.byte	0
	.uleb128 0xf
	.long	0x2c7
	.long	.LBB43
	.long	.Ldebug_ranges0+0x60
	.byte	0x1
	.byte	0x1f
	.long	0x42f
	.uleb128 0x11
	.long	.Ldebug_ranges0+0x60
	.uleb128 0x12
	.long	0x2d3
	.long	.LLST15
	.uleb128 0x12
	.long	0x2de
	.long	.LLST16
	.uleb128 0x13
	.long	0x273
	.long	.LBB45
	.long	.Ldebug_ranges0+0xa0
	.byte	0x1
	.byte	0x35
	.uleb128 0x10
	.long	0x2af
	.long	.LLST17
	.uleb128 0x10
	.long	0x2a4
	.long	.LLST18
	.uleb128 0x10
	.long	0x299
	.long	.LLST19
	.uleb128 0x10
	.long	0x28e
	.long	.LLST20
	.uleb128 0x10
	.long	0x283
	.long	.LLST21
	.byte	0
	.byte	0
	.byte	0
	.uleb128 0xf
	.long	0x273
	.long	.LBB71
	.long	.Ldebug_ranges0+0xe8
	.byte	0x1
	.byte	0x1e
	.long	0x470
	.uleb128 0x10
	.long	0x2af
	.long	.LLST22
	.uleb128 0x10
	.long	0x2a4
	.long	.LLST23
	.uleb128 0x10
	.long	0x299
	.long	.LLST24
	.uleb128 0x10
	.long	0x28e
	.long	.LLST25
	.uleb128 0x10
	.long	0x283
	.long	.LLST26
	.byte	0
	.uleb128 0x13
	.long	0x2bb
	.long	.LBB78
	.long	.Ldebug_ranges0+0x108
	.byte	0x1
	.byte	0x20
	.uleb128 0x14
	.long	.LVL7
	.long	0x547
	.uleb128 0x15
	.long	.LVL8
	.long	0x552
	.byte	0
	.byte	0
	.uleb128 0x16
	.long	0x273
	.long	.LASF34
	.long	.LFB1
	.long	.LFE1-.LFB1
	.uleb128 0x1
	.byte	0x9c
	.long	0x4d3
	.uleb128 0x17
	.long	0x283
	.uleb128 0x2
	.byte	0x91
	.sleb128 0
	.uleb128 0x17
	.long	0x28e
	.uleb128 0x2
	.byte	0x91
	.sleb128 4
	.uleb128 0x17
	.long	0x299
	.uleb128 0x2
	.byte	0x91
	.sleb128 8
	.uleb128 0x17
	.long	0x2a4
	.uleb128 0x2
	.byte	0x91
	.sleb128 12
	.uleb128 0x17
	.long	0x2af
	.uleb128 0x2
	.byte	0x91
	.sleb128 16
	.byte	0
	.uleb128 0x16
	.long	0x2bb
	.long	.LASF35
	.long	.LFB3
	.long	.LFE3-.LFB3
	.uleb128 0x1
	.byte	0x9c
	.long	0x4fd
	.uleb128 0x14
	.long	.LVL10
	.long	0x547
	.uleb128 0x15
	.long	.LVL11
	.long	0x552
	.byte	0
	.uleb128 0x18
	.long	.LASF14
	.byte	0x1
	.byte	0x11
	.long	0x106
	.uleb128 0x5
	.byte	0x3
	.long	_ZL7gdt_ptr
	.uleb128 0x19
	.long	0xb1
	.long	0x51e
	.uleb128 0x1a
	.long	0x51e
	.byte	0x5
	.byte	0
	.uleb128 0x2
	.byte	0x4
	.byte	0x7
	.long	.LASF36
	.uleb128 0x18
	.long	.LASF37
	.byte	0x1
	.byte	0x12
	.long	0x50e
	.uleb128 0x5
	.byte	0x3
	.long	_ZL7entries
	.uleb128 0x18
	.long	.LASF38
	.byte	0x1
	.byte	0x13
	.long	0x25c
	.uleb128 0x5
	.byte	0x3
	.long	_ZL9tss_entry
	.uleb128 0x1b
	.long	.LASF39
	.long	.LASF39
	.byte	0x1
	.byte	0x22
	.uleb128 0x1b
	.long	.LASF40
	.long	.LASF40
	.byte	0x1
	.byte	0x2f
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
	.uleb128 0x7
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
	.uleb128 0x8
	.uleb128 0x3b
	.byte	0
	.uleb128 0x3
	.uleb128 0xe
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
	.uleb128 0x20
	.uleb128 0xb
	.byte	0
	.byte	0
	.uleb128 0xc
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
	.uleb128 0xf
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
	.uleb128 0x10
	.uleb128 0x5
	.byte	0
	.uleb128 0x31
	.uleb128 0x13
	.uleb128 0x2
	.uleb128 0x17
	.byte	0
	.byte	0
	.uleb128 0x11
	.uleb128 0xb
	.byte	0x1
	.uleb128 0x55
	.uleb128 0x17
	.byte	0
	.byte	0
	.uleb128 0x12
	.uleb128 0x34
	.byte	0
	.uleb128 0x31
	.uleb128 0x13
	.uleb128 0x2
	.uleb128 0x17
	.byte	0
	.byte	0
	.uleb128 0x13
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
	.byte	0
	.byte	0
	.uleb128 0x14
	.uleb128 0x4109
	.byte	0
	.uleb128 0x11
	.uleb128 0x1
	.uleb128 0x31
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0x15
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
	.uleb128 0x16
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
	.uleb128 0x17
	.uleb128 0x5
	.byte	0
	.uleb128 0x31
	.uleb128 0x13
	.uleb128 0x2
	.uleb128 0x18
	.byte	0
	.byte	0
	.uleb128 0x18
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
	.uleb128 0x19
	.uleb128 0x1
	.byte	0x1
	.uleb128 0x49
	.uleb128 0x13
	.uleb128 0x1
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0x1a
	.uleb128 0x21
	.byte	0
	.uleb128 0x49
	.uleb128 0x13
	.uleb128 0x2f
	.uleb128 0xb
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
	.byte	0
	.section	.debug_loc,"",@progbits
.Ldebug_loc0:
.LLST0:
	.long	.LVL2-.Ltext0
	.long	.LVL3-.Ltext0
	.value	0x3
	.byte	0x9
	.byte	0xcf
	.byte	0x9f
	.long	0
	.long	0
.LLST1:
	.long	.LVL2-.Ltext0
	.long	.LVL3-.Ltext0
	.value	0x3
	.byte	0x9
	.byte	0xfa
	.byte	0x9f
	.long	0
	.long	0
.LLST2:
	.long	.LVL2-.Ltext0
	.long	.LVL3-.Ltext0
	.value	0x3
	.byte	0x9
	.byte	0xff
	.byte	0x9f
	.long	0
	.long	0
.LLST3:
	.long	.LVL2-.Ltext0
	.long	.LVL3-.Ltext0
	.value	0x2
	.byte	0x30
	.byte	0x9f
	.long	0
	.long	0
.LLST4:
	.long	.LVL2-.Ltext0
	.long	.LVL3-.Ltext0
	.value	0x2
	.byte	0x33
	.byte	0x9f
	.long	0
	.long	0
.LLST5:
	.long	.LVL0-.Ltext0
	.long	.LVL1-.Ltext0
	.value	0x3
	.byte	0x9
	.byte	0xcf
	.byte	0x9f
	.long	0
	.long	0
.LLST6:
	.long	.LVL0-.Ltext0
	.long	.LVL1-.Ltext0
	.value	0x3
	.byte	0x9
	.byte	0x9a
	.byte	0x9f
	.long	0
	.long	0
.LLST7:
	.long	.LVL0-.Ltext0
	.long	.LVL1-.Ltext0
	.value	0x3
	.byte	0x9
	.byte	0xff
	.byte	0x9f
	.long	0
	.long	0
.LLST8:
	.long	.LVL0-.Ltext0
	.long	.LVL1-.Ltext0
	.value	0x2
	.byte	0x30
	.byte	0x9f
	.long	0
	.long	0
.LLST9:
	.long	.LVL0-.Ltext0
	.long	.LVL1-.Ltext0
	.value	0x2
	.byte	0x31
	.byte	0x9f
	.long	0
	.long	0
.LLST10:
	.long	.LVL1-.Ltext0
	.long	.LVL2-.Ltext0
	.value	0x3
	.byte	0x9
	.byte	0xcf
	.byte	0x9f
	.long	0
	.long	0
.LLST11:
	.long	.LVL1-.Ltext0
	.long	.LVL2-.Ltext0
	.value	0x3
	.byte	0x9
	.byte	0x92
	.byte	0x9f
	.long	0
	.long	0
.LLST12:
	.long	.LVL1-.Ltext0
	.long	.LVL2-.Ltext0
	.value	0x3
	.byte	0x9
	.byte	0xff
	.byte	0x9f
	.long	0
	.long	0
.LLST13:
	.long	.LVL1-.Ltext0
	.long	.LVL2-.Ltext0
	.value	0x2
	.byte	0x30
	.byte	0x9f
	.long	0
	.long	0
.LLST14:
	.long	.LVL1-.Ltext0
	.long	.LVL2-.Ltext0
	.value	0x2
	.byte	0x32
	.byte	0x9f
	.long	0
	.long	0
.LLST15:
	.long	.LVL4-.Ltext0
	.long	.LVL6-.Ltext0
	.value	0x6
	.byte	0x3
	.long	_ZL9tss_entry
	.byte	0x9f
	.long	0
	.long	0
.LLST16:
	.long	.LVL4-.Ltext0
	.long	.LVL6-.Ltext0
	.value	0x6
	.byte	0x3
	.long	_ZL9tss_entry+104
	.byte	0x9f
	.long	0
	.long	0
.LLST17:
	.long	.LVL4-.Ltext0
	.long	.LVL5-.Ltext0
	.value	0x2
	.byte	0x30
	.byte	0x9f
	.long	0
	.long	0
.LLST18:
	.long	.LVL4-.Ltext0
	.long	.LVL5-.Ltext0
	.value	0x3
	.byte	0x9
	.byte	0xe9
	.byte	0x9f
	.long	0
	.long	0
.LLST19:
	.long	.LVL4-.Ltext0
	.long	.LVL5-.Ltext0
	.value	0x6
	.byte	0x3
	.long	_ZL9tss_entry+104
	.byte	0x9f
	.long	0
	.long	0
.LLST20:
	.long	.LVL4-.Ltext0
	.long	.LVL5-.Ltext0
	.value	0x6
	.byte	0x3
	.long	_ZL9tss_entry
	.byte	0x9f
	.long	0
	.long	0
.LLST21:
	.long	.LVL4-.Ltext0
	.long	.LVL5-.Ltext0
	.value	0x2
	.byte	0x35
	.byte	0x9f
	.long	0
	.long	0
.LLST22:
	.long	.LVL3-.Ltext0
	.long	.LVL4-.Ltext0
	.value	0x3
	.byte	0x9
	.byte	0xcf
	.byte	0x9f
	.long	0
	.long	0
.LLST23:
	.long	.LVL3-.Ltext0
	.long	.LVL4-.Ltext0
	.value	0x3
	.byte	0x9
	.byte	0xf2
	.byte	0x9f
	.long	0
	.long	0
.LLST24:
	.long	.LVL3-.Ltext0
	.long	.LVL4-.Ltext0
	.value	0x3
	.byte	0x9
	.byte	0xff
	.byte	0x9f
	.long	0
	.long	0
.LLST25:
	.long	.LVL3-.Ltext0
	.long	.LVL4-.Ltext0
	.value	0x2
	.byte	0x30
	.byte	0x9f
	.long	0
	.long	0
.LLST26:
	.long	.LVL3-.Ltext0
	.long	.LVL4-.Ltext0
	.value	0x2
	.byte	0x34
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
	.long	.LBB30-.Ltext0
	.long	.LBE30-.Ltext0
	.long	.LBB42-.Ltext0
	.long	.LBE42-.Ltext0
	.long	.LBB87-.Ltext0
	.long	.LBE87-.Ltext0
	.long	0
	.long	0
	.long	.LBB34-.Ltext0
	.long	.LBE34-.Ltext0
	.long	.LBB69-.Ltext0
	.long	.LBE69-.Ltext0
	.long	.LBB85-.Ltext0
	.long	.LBE85-.Ltext0
	.long	0
	.long	0
	.long	.LBB38-.Ltext0
	.long	.LBE38-.Ltext0
	.long	.LBB67-.Ltext0
	.long	.LBE67-.Ltext0
	.long	.LBB86-.Ltext0
	.long	.LBE86-.Ltext0
	.long	0
	.long	0
	.long	.LBB43-.Ltext0
	.long	.LBE43-.Ltext0
	.long	.LBB68-.Ltext0
	.long	.LBE68-.Ltext0
	.long	.LBB70-.Ltext0
	.long	.LBE70-.Ltext0
	.long	.LBB75-.Ltext0
	.long	.LBE75-.Ltext0
	.long	.LBB77-.Ltext0
	.long	.LBE77-.Ltext0
	.long	.LBB83-.Ltext0
	.long	.LBE83-.Ltext0
	.long	.LBB89-.Ltext0
	.long	.LBE89-.Ltext0
	.long	0
	.long	0
	.long	.LBB45-.Ltext0
	.long	.LBE45-.Ltext0
	.long	.LBB54-.Ltext0
	.long	.LBE54-.Ltext0
	.long	.LBB55-.Ltext0
	.long	.LBE55-.Ltext0
	.long	.LBB56-.Ltext0
	.long	.LBE56-.Ltext0
	.long	.LBB57-.Ltext0
	.long	.LBE57-.Ltext0
	.long	.LBB58-.Ltext0
	.long	.LBE58-.Ltext0
	.long	.LBB59-.Ltext0
	.long	.LBE59-.Ltext0
	.long	.LBB60-.Ltext0
	.long	.LBE60-.Ltext0
	.long	0
	.long	0
	.long	.LBB71-.Ltext0
	.long	.LBE71-.Ltext0
	.long	.LBB76-.Ltext0
	.long	.LBE76-.Ltext0
	.long	.LBB88-.Ltext0
	.long	.LBE88-.Ltext0
	.long	0
	.long	0
	.long	.LBB78-.Ltext0
	.long	.LBE78-.Ltext0
	.long	.LBB84-.Ltext0
	.long	.LBE84-.Ltext0
	.long	.LBB90-.Ltext0
	.long	.LBE90-.Ltext0
	.long	.LBB91-.Ltext0
	.long	.LBE91-.Ltext0
	.long	0
	.long	0
	.section	.debug_line,"",@progbits
.Ldebug_line0:
	.section	.debug_str,"MS",@progbits,1
.LASF12:
	.string	"limit"
.LASF44:
	.string	"decltype(nullptr)"
.LASF1:
	.string	"short int"
.LASF48:
	.string	"init_gdt"
.LASF28:
	.string	"eflags"
.LASF43:
	.string	"/home/pfalcato/Spartix/kernel"
.LASF34:
	.string	"_Z17create_descriptormmmhh"
.LASF18:
	.string	"base_middle"
.LASF25:
	.string	"esp0"
.LASF41:
	.string	"GNU C++11 5.3.0 -mtune=generic -march=pentiumpro -g -O2 -std=c++11 -ffreestanding -fbuiltin -fstack-protector-strong -fno-exceptions -fno-rtti"
.LASF37:
	.string	"entries"
.LASF5:
	.string	"uint8_t"
.LASF30:
	.string	"iomap_base"
.LASF33:
	.string	"entrynum"
.LASF3:
	.string	"long long int"
.LASF45:
	.string	"create_descriptor"
.LASF2:
	.string	"long int"
.LASF20:
	.string	"granularity"
.LASF36:
	.string	"sizetype"
.LASF29:
	.string	"trap"
.LASF16:
	.string	"limit_low"
.LASF22:
	.string	"gdt_ptr_t"
.LASF49:
	.string	"_Z8init_gdtv"
.LASF32:
	.string	"long double"
.LASF4:
	.string	"unsigned char"
.LASF19:
	.string	"access"
.LASF0:
	.string	"signed char"
.LASF10:
	.string	"long long unsigned int"
.LASF8:
	.string	"uint32_t"
.LASF11:
	.string	"unsigned int"
.LASF6:
	.string	"uint16_t"
.LASF24:
	.string	"prev_tss"
.LASF39:
	.string	"GDT_Flush"
.LASF7:
	.string	"short unsigned int"
.LASF26:
	.string	"esp1"
.LASF27:
	.string	"esp2"
.LASF35:
	.string	"_Z8load_gdtv"
.LASF21:
	.string	"base_high"
.LASF9:
	.string	"long unsigned int"
.LASF42:
	.string	"arch/i386/gdt.cpp"
.LASF15:
	.string	"gdt_entry_struct"
.LASF46:
	.string	"load_gdt"
.LASF47:
	.string	"install_tss"
.LASF17:
	.string	"base_low"
.LASF40:
	.string	"tss_flush"
.LASF23:
	.string	"tss_entry_struct"
.LASF13:
	.string	"base"
.LASF38:
	.string	"tss_entry"
.LASF14:
	.string	"gdt_ptr"
.LASF31:
	.string	"tss_entry_t"
	.ident	"GCC: (GNU) 5.3.0"
