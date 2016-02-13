	.file	"vmm.cpp"
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
	.type	_Z7kmunmapPvm.part.0, @function
_Z7kmunmapPvm.part.0:
.LFB28:
	.file 1 "arch/i386/vmm.cpp"
	.loc 1 183 0
	.cfi_startproc
.LVL0:
.LBB136:
.LBB137:
	.loc 1 84 0
	movl	_cur_directory, %ecx
.LBE137:
.LBE136:
	.loc 1 190 0
	testl	%ecx, %ecx
	je	.L20
	.loc 1 183 0
	pushl	%ebp
	.cfi_def_cfa_offset 8
	.cfi_offset 5, -8
	pushl	%edi
	.cfi_def_cfa_offset 12
	.cfi_offset 7, -12
	pushl	%esi
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	pushl	%ebx
	.cfi_def_cfa_offset 20
	.cfi_offset 3, -20
	.loc 1 192 0
	movl	%eax, %ebx
.LVL1:
	.loc 1 193 0
	shrl	$22, %eax
.LVL2:
	.loc 1 183 0
	subl	$28, %esp
	.cfi_def_cfa_offset 48
	.loc 1 193 0
	movl	(%ecx,%eax,4), %edi
	testl	$1, %edi
	je	.L1
	.loc 1 196 0
	movl	%ebx, %eax
	.loc 1 195 0
	andl	$2147479552, %edi
.LVL3:
	.loc 1 196 0
	shrl	$12, %eax
	andl	$1023, %eax
	movl	(%edi,%eax,4), %ecx
.LVL4:
	testb	$1, %cl
	je	.L1
.LVL5:
.LBB138:
	.loc 1 198 0
	testl	%edx, %edx
	je	.L1
	movl	%edx, 12(%esp)
	xorl	%ebp, %ebp
	jmp	.L5
.LVL6:
	.align 16
.L22:
	movl	%ebx, %eax
	shrl	$12, %eax
	andl	$1023, %eax
	movl	(%edi,%eax,4), %ecx
.LVL7:
.L5:
.LBB139:
	.loc 1 200 0
	movl	%ebx, %eax
.LBB140:
.LBB141:
	.loc 1 54 0
	movl	%ecx, %edx
.LBE141:
.LBE140:
	.loc 1 200 0
	shrl	$12, %eax
	andl	$1023, %eax
.LBB146:
.LBB144:
	.loc 1 54 0
	andl	$2147479552, %edx
.LBE144:
.LBE146:
	.loc 1 200 0
	movl	%eax, %esi
.LVL8:
.LBB147:
.LBB145:
	.loc 1 54 0
	je	.L4
	.loc 1 55 0
	subl	$8, %esp
	.cfi_def_cfa_offset 56
	pushl	%edx
	.cfi_def_cfa_offset 60
	pushl	$1
	.cfi_def_cfa_offset 64
	call	_Z5pfreemPv
.LVL9:
	movl	(%edi,%esi,4), %ecx
	addl	$16, %esp
	.cfi_def_cfa_offset 48
.L4:
.LVL10:
.LBB142:
.LBB143:
	.file 2 "include/kernel/vmm.h"
	.loc 2 89 0
	andl	$-2, %ecx
	movl	%ecx, (%edi,%esi,4)
.LVL11:
.LBE143:
.LBE142:
.LBE145:
.LBE147:
.LBB148:
.LBB149:
	.loc 2 146 0
/APP
/  146 "include/kernel/vmm.h" 1
	invlpg (%ebx)
/  0 "" 2
.LVL12:
/NO_APP
.LBE149:
.LBE148:
.LBE139:
	.loc 1 198 0
	addl	$1, %ebp
.LVL13:
	addl	$4096, %ebx
.LVL14:
	cmpl	%ebp, 12(%esp)
	jne	.L22
.LVL15:
.L1:
.LBE138:
	.loc 1 205 0
	addl	$28, %esp
	.cfi_def_cfa_offset 20
	popl	%ebx
	.cfi_restore 3
	.cfi_def_cfa_offset 16
	popl	%esi
	.cfi_restore 6
	.cfi_def_cfa_offset 12
	popl	%edi
	.cfi_restore 7
	.cfi_def_cfa_offset 8
	popl	%ebp
	.cfi_restore 5
	.cfi_def_cfa_offset 4
.L20:
	rep ret
	.cfi_endproc
.LFE28:
	.size	_Z7kmunmapPvm.part.0, .-_Z7kmunmapPvm.part.0
	.section	.text.unlikely
.LCOLDE0:
	.text
.LHOTE0:
	.section	.text.unlikely
.LCOLDB1:
	.text
.LHOTB1:
	.align 16
	.globl	_Z16switch_directoryPN3VMM10pdirectoryE
	.type	_Z16switch_directoryPN3VMM10pdirectoryE, @function
_Z16switch_directoryPN3VMM10pdirectoryE:
.LFB20:
	.loc 1 73 0
	.cfi_startproc
.LVL16:
	subl	$12, %esp
	.cfi_def_cfa_offset 16
	movl	$1, %eax
	.loc 1 73 0
	movl	16(%esp), %edx
	.loc 1 75 0
	testl	%edx, %edx
	je	.L24
	.loc 1 78 0
	subl	$12, %esp
	.cfi_def_cfa_offset 28
	.loc 1 77 0
	movl	%edx, _cur_directory
	.loc 1 78 0
	pushl	%edx
	.cfi_def_cfa_offset 32
	call	loadPageDirectory
.LVL17:
	.loc 1 79 0
	addl	$16, %esp
	.cfi_def_cfa_offset 16
	xorl	%eax, %eax
.L24:
	.loc 1 80 0
	addl	$12, %esp
	.cfi_def_cfa_offset 4
	ret
	.cfi_endproc
.LFE20:
	.size	_Z16switch_directoryPN3VMM10pdirectoryE, .-_Z16switch_directoryPN3VMM10pdirectoryE
	.section	.text.unlikely
.LCOLDE1:
	.text
.LHOTE1:
	.section	.text.unlikely
.LCOLDB2:
	.text
.LHOTB2:
	.align 16
	.globl	_Z13get_directoryv
	.type	_Z13get_directoryv, @function
_Z13get_directoryv:
.LFB21:
	.loc 1 82 0
	.cfi_startproc
.LVL18:
	.loc 1 86 0
	movl	_cur_directory, %eax
	ret
	.cfi_endproc
.LFE21:
	.size	_Z13get_directoryv, .-_Z13get_directoryv
	.section	.text.unlikely
.LCOLDE2:
	.text
.LHOTE2:
	.section	.text.unlikely
.LCOLDB3:
	.text
.LHOTB3:
	.align 16
	.globl	_ZN3VMM4InitEv
	.type	_ZN3VMM4InitEv, @function
_ZN3VMM4InitEv:
.LFB22:
	.loc 1 89 0
	.cfi_startproc
.LVL19:
	pushl	%edi
	.cfi_def_cfa_offset 8
	.cfi_offset 7, -8
	pushl	%ebx
	.cfi_def_cfa_offset 12
	.cfi_offset 3, -12
	.loc 1 91 0
	movl	$-2143354880, %ebx
	xorl	%eax, %eax
	movl	$1024, %ecx
	movl	%ebx, %edi
	.loc 1 89 0
	subl	$4, %esp
	.cfi_def_cfa_offset 16
	.loc 1 91 0
	rep stosl
.LVL20:
	.loc 1 93 0
	movl	$1024, %ecx
	rep stosl
.LVL21:
	.align 16
.L31:
.LBB150:
.LBB151:
	.loc 1 102 0 discriminator 2
	movl	%eax, %edx
	movl	%eax, %ecx
.LBE151:
	.loc 1 95 0 discriminator 2
	addl	$4096, %eax
.LVL22:
.LBB152:
	.loc 1 102 0 discriminator 2
	sarl	$12, %edx
.LVL23:
	orl	$5, %ecx
.LVL24:
.LBE152:
	.loc 1 95 0 discriminator 2
	cmpl	$4194304, %eax
.LBB153:
	.loc 1 102 0 discriminator 2
	movl	%ecx, -2143354880(,%edx,4)
.LVL25:
.LBE153:
	.loc 1 95 0 discriminator 2
	jne	.L31
	xorl	%eax, %eax
.LVL26:
	.align 16
.L32:
.LBE150:
.LBB154:
.LBB155:
	.loc 1 111 0 discriminator 2
	movl	%eax, %edx
	movl	%eax, %ecx
.LBE155:
	.loc 1 104 0 discriminator 2
	addl	$4096, %eax
.LVL27:
.LBB156:
	.loc 1 111 0 discriminator 2
	sall	$10, %edx
.LVL28:
	orl	$5, %ecx
.LVL29:
	shrl	$22, %edx
.LBE156:
	.loc 1 104 0 discriminator 2
	cmpl	$4194304, %eax
.LBB157:
	.loc 1 111 0 discriminator 2
	movl	%ecx, -2143350784(,%edx,4)
.LVL30:
.LBE157:
	.loc 1 104 0 discriminator 2
	jne	.L32
.LVL31:
.LBE154:
	.loc 1 114 0
	movl	$-2143346688, %edx
	xorl	%eax, %eax
.LVL32:
	movl	$1024, %ecx
	movl	%edx, %edi
.LBB158:
.LBB159:
	.loc 1 78 0
	subl	$12, %esp
	.cfi_def_cfa_offset 28
.LBE159:
.LBE158:
	.loc 1 114 0
	rep stosl
.LVL33:
.LBB161:
.LBB162:
	.loc 2 118 0
	movl	-2143344640, %eax
	andl	$-2147479553, %eax
	orl	$4128775, %eax
	movl	%eax, -2143344640
.LVL34:
.LBE162:
.LBE161:
.LBB163:
.LBB164:
	movl	-2143346688, %eax
	andl	$-2147479553, %eax
	orl	$4132871, %eax
	movl	%eax, -2143346688
.LVL35:
.LBE164:
.LBE163:
.LBB165:
.LBB166:
	movl	-2143342596, %eax
	andl	$-2147479553, %eax
	orl	$4136963, %eax
	movl	%eax, -2143342596
.LVL36:
.LBE166:
.LBE165:
.LBB167:
.LBB160:
	.loc 1 78 0
	pushl	$4136960
	.cfi_def_cfa_offset 32
	.loc 1 77 0
	movl	$4136960, _cur_directory
	.loc 1 78 0
	call	loadPageDirectory
.LVL37:
.LBE160:
.LBE167:
	.loc 1 133 0
	addl	$20, %esp
	.cfi_def_cfa_offset 12
	popl	%ebx
	.cfi_restore 3
	.cfi_def_cfa_offset 8
	popl	%edi
	.cfi_restore 7
	.cfi_def_cfa_offset 4
	ret
	.cfi_endproc
.LFE22:
	.size	_ZN3VMM4InitEv, .-_ZN3VMM4InitEv
	.section	.text.unlikely
.LCOLDE3:
	.text
.LHOTE3:
	.section	.rodata.str1.1,"aMS",@progbits,1
.LC4:
	.string	"No free blocks"
.LC5:
	.string	"Failed to map page 0x%X\n"
.LC6:
	.string	"No more physical memory"
	.section	.text.unlikely
.LCOLDB7:
	.text
.LHOTB7:
	.align 16
	.globl	_Z5kmmapmm
	.type	_Z5kmmapmm, @function
_Z5kmmapmm:
.LFB23:
	.loc 1 135 0
	.cfi_startproc
.LVL38:
	pushl	%ebp
	.cfi_def_cfa_offset 8
	.cfi_offset 5, -8
	pushl	%edi
	.cfi_def_cfa_offset 12
	.cfi_offset 7, -12
	pushl	%esi
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	pushl	%ebx
	.cfi_def_cfa_offset 20
	.cfi_offset 3, -20
	subl	$28, %esp
	.cfi_def_cfa_offset 48
	.loc 1 135 0
	movl	52(%esp), %eax
	.loc 1 136 0
	testl	%eax, %eax
	je	.L49
.LBB168:
.LBB169:
	.loc 1 84 0
	movl	_cur_directory, %edx
.LBE169:
.LBE168:
	.loc 1 139 0
	testl	%edx, %edx
	je	.L58
	cmpl	$1024, %eax
	movl	$1024, %esi
	cmovbe	%eax, %esi
	movl	48(%esp), %eax
	movl	%esi, 12(%esp)
.LVL39:
	shrl	$22, %eax
.LVL40:
	leal	(%edx,%eax,4), %ebp
	.loc 1 145 0
	movl	0(%ebp), %ebx
	testb	$-128, %bl
	jne	.L59
.L39:
.LBB170:
	.loc 1 148 0
	cmpl	$1024, 12(%esp)
	je	.L60
.LBE170:
	.loc 1 156 0
	movl	%ebx, %esi
.LVL41:
	andl	$1, %esi
	je	.L40
	.loc 1 157 0
	andl	$2147479552, %ebx
.LVL42:
.L41:
.LBB178:
	.loc 1 168 0
	movl	48(%esp), %ebp
.LVL43:
	xorl	%edi, %edi
	xorl	%esi, %esi
	jmp	.L45
.LVL44:
	.align 16
.L62:
.LBB179:
	.loc 1 178 0
	movl	%ebp, %ecx
	orl	$1, %eax
.LVL45:
.LBE179:
	.loc 1 168 0
	addl	$1, %edi
.LVL46:
.LBB182:
	.loc 1 178 0
	sarl	$12, %ecx
.LBE182:
	.loc 1 168 0
	addl	$4096, %ebp
.LVL47:
.LBB183:
	.loc 1 178 0
	andl	$1023, %ecx
.LBE183:
	.loc 1 168 0
	cmpl	12(%esp), %edi
.LBB184:
	.loc 1 178 0
	movl	%eax, (%ebx,%ecx,4)
.LVL48:
.LBE184:
	.loc 1 168 0
	je	.L61
.LVL49:
.L45:
.LBB185:
	.loc 1 170 0
	testl	%edi, %edi
	cmove	%ebp, %esi
.LVL50:
.LBB180:
.LBB181:
	.loc 1 43 0
	subl	$12, %esp
	.cfi_remember_state
	.cfi_def_cfa_offset 60
	pushl	$1
	.cfi_def_cfa_offset 64
	call	_Z7pmallocm
.LVL51:
	.loc 1 44 0
	addl	$16, %esp
	.cfi_def_cfa_offset 48
	testl	%eax, %eax
	jne	.L62
.LVL52:
.LBE181:
.LBE180:
	.loc 1 174 0
	subl	$8, %esp
	.cfi_def_cfa_offset 56
	pushl	%ebp
	.cfi_def_cfa_offset 60
	pushl	$.LC5
	.cfi_def_cfa_offset 64
	call	printf
.LVL53:
	.loc 1 175 0
	movl	$.LC6, (%esp)
	call	_Z5panicPKc
.LVL54:
	.align 16
.L61:
	.cfi_restore_state
	movl	%esi, %eax
.LVL55:
.L54:
.LBE185:
.LBE178:
	.loc 1 181 0
	addl	$28, %esp
	.cfi_remember_state
	.cfi_def_cfa_offset 20
	popl	%ebx
	.cfi_restore 3
	.cfi_def_cfa_offset 16
	popl	%esi
	.cfi_restore 6
	.cfi_def_cfa_offset 12
	popl	%edi
	.cfi_restore 7
	.cfi_def_cfa_offset 8
	popl	%ebp
	.cfi_restore 5
	.cfi_def_cfa_offset 4
	ret
.LVL56:
	.align 16
.L59:
	.cfi_restore_state
	.loc 1 145 0 discriminator 1
	testl	$2147479552, %ebx
	je	.L39
.LVL57:
.L49:
	.loc 1 181 0
	addl	$28, %esp
	.cfi_remember_state
	.cfi_def_cfa_offset 20
	.loc 1 137 0
	xorl	%eax, %eax
	.loc 1 181 0
	popl	%ebx
	.cfi_restore 3
	.cfi_def_cfa_offset 16
	popl	%esi
	.cfi_restore 6
	.cfi_def_cfa_offset 12
	popl	%edi
	.cfi_restore 7
	.cfi_def_cfa_offset 8
	popl	%ebp
	.cfi_restore 5
	.cfi_def_cfa_offset 4
	ret
.LVL58:
	.align 16
.L40:
	.cfi_restore_state
	.loc 1 159 0
	subl	$12, %esp
	.cfi_def_cfa_offset 60
	pushl	$1
	.cfi_def_cfa_offset 64
	call	_Z7pmallocm
.LVL59:
	.loc 1 160 0
	addl	$16, %esp
	.cfi_def_cfa_offset 48
	testl	%eax, %eax
	.loc 1 159 0
	movl	%eax, %ebx
.LVL60:
	.loc 1 160 0
	je	.L63
	.loc 1 162 0
	leal	4(%eax), %edi
	movl	%eax, %ecx
	movl	$0, (%eax)
.LVL61:
	movl	$0, 4092(%eax)
	movl	%esi, %eax
.LVL62:
	andl	$-4, %edi
	subl	%edi, %ecx
.LVL63:
	addl	$4096, %ecx
	shrl	$2, %ecx
	rep stosl
.LVL64:
.LBB186:
.LBB187:
	.loc 2 118 0
	movl	0(%ebp), %eax
	andl	$-2147479553, %eax
	orl	$3, %eax
	orl	%ebx, %eax
	movl	%eax, 0(%ebp)
	jmp	.L41
.LVL65:
.L60:
.LBE187:
.LBE186:
.LBB188:
.LBB171:
	.loc 1 152 0
	subl	$12, %esp
	.cfi_def_cfa_offset 60
.LBB172:
.LBB173:
	.loc 2 110 0
	orb	$-125, %bl
	movl	%ebx, 0(%ebp)
.LVL66:
.LBE173:
.LBE172:
	.loc 1 152 0
	pushl	$1024
	.cfi_def_cfa_offset 64
	call	_Z7pmallocm
.LVL67:
.LBB174:
.LBB175:
	.loc 2 118 0
	movl	0(%ebp), %edx
.LBE175:
.LBE174:
	.loc 1 154 0
	addl	$16, %esp
	.cfi_def_cfa_offset 48
.LBB177:
.LBB176:
	.loc 2 118 0
	andl	$-2147479553, %edx
	orl	%eax, %edx
	movl	%edx, 0(%ebp)
.LVL68:
.LBE176:
.LBE177:
	.loc 1 154 0
	jmp	.L54
.LVL69:
.L63:
.LBE171:
.LBE188:
	.loc 1 161 0
	subl	$12, %esp
	.cfi_remember_state
	.cfi_def_cfa_offset 60
	pushl	$.LC4
	.cfi_def_cfa_offset 64
	call	_Z5panicPKc
.LVL70:
.L58:
	.cfi_restore_state
	.loc 1 140 0
	call	abort
.LVL71:
	.cfi_endproc
.LFE23:
	.size	_Z5kmmapmm, .-_Z5kmmapmm
	.section	.text.unlikely
.LCOLDE7:
	.text
.LHOTE7:
	.section	.text.unlikely
.LCOLDB8:
	.text
.LHOTB8:
	.align 16
	.globl	_Z7kmunmapPvm
	.type	_Z7kmunmapPvm, @function
_Z7kmunmapPvm:
.LFB24:
	.loc 1 184 0
	.cfi_startproc
.LVL72:
	.loc 1 184 0
	movl	4(%esp), %eax
	movl	8(%esp), %edx
	.loc 1 187 0
	testl	%eax, %eax
	je	.L64
	testl	%edx, %edx
	je	.L64
	jmp	_Z7kmunmapPvm.part.0
.LVL73:
	.align 16
.L64:
	rep ret
	.cfi_endproc
.LFE24:
	.size	_Z7kmunmapPvm, .-_Z7kmunmapPvm
	.section	.text.unlikely
.LCOLDE8:
	.text
.LHOTE8:
	.section	.text.unlikely
.LCOLDB9:
	.text
.LHOTB9:
	.align 16
	.globl	_Z7vmallocm
	.type	_Z7vmallocm, @function
_Z7vmallocm:
.LFB25:
	.loc 1 207 0
	.cfi_startproc
.LVL74:
	pushl	%esi
	.cfi_def_cfa_offset 8
	.cfi_offset 6, -8
	pushl	%ebx
	.cfi_def_cfa_offset 12
	.cfi_offset 3, -12
	subl	$4, %esp
	.cfi_def_cfa_offset 16
	.loc 1 207 0
	movl	16(%esp), %esi
	.loc 1 208 0
	testl	%esi, %esi
	je	.L69
	.loc 1 210 0
	subl	$12, %esp
	.cfi_def_cfa_offset 28
	pushl	%esi
	.cfi_def_cfa_offset 32
	call	_Z7pmallocm
.LVL75:
	.loc 1 211 0
	addl	$16, %esp
	.cfi_def_cfa_offset 16
	testl	%eax, %eax
	.loc 1 210 0
	movl	%eax, %ebx
.LVL76:
	.loc 1 211 0
	je	.L69
	.loc 1 213 0
	subl	$8, %esp
	.cfi_def_cfa_offset 24
	pushl	%eax
	.cfi_def_cfa_offset 28
	pushl	%esi
	.cfi_def_cfa_offset 32
	call	_Z5pfreemPv
.LVL77:
	.loc 1 214 0
	popl	%eax
	.cfi_def_cfa_offset 28
	popl	%edx
	.cfi_def_cfa_offset 24
	pushl	%esi
	.cfi_def_cfa_offset 28
	pushl	%ebx
	.cfi_def_cfa_offset 32
	call	_Z5kmmapmm
.LVL78:
	addl	$16, %esp
	.cfi_def_cfa_offset 16
	testl	%eax, %eax
	je	.L69
	.loc 1 217 0
	addl	$4, %esp
	.cfi_remember_state
	.cfi_def_cfa_offset 12
	movl	%ebx, %eax
	popl	%ebx
	.cfi_restore 3
	.cfi_def_cfa_offset 8
.LVL79:
	popl	%esi
	.cfi_restore 6
	.cfi_def_cfa_offset 4
	ret
.LVL80:
	.align 16
.L69:
	.cfi_restore_state
	addl	$4, %esp
	.cfi_def_cfa_offset 12
	.loc 1 209 0
	xorl	%eax, %eax
	.loc 1 217 0
	popl	%ebx
	.cfi_restore 3
	.cfi_def_cfa_offset 8
	popl	%esi
	.cfi_restore 6
	.cfi_def_cfa_offset 4
	ret
	.cfi_endproc
.LFE25:
	.size	_Z7vmallocm, .-_Z7vmallocm
	.section	.text.unlikely
.LCOLDE9:
	.text
.LHOTE9:
	.section	.text.unlikely
.LCOLDB10:
	.text
.LHOTB10:
	.align 16
	.globl	_Z5vfreePvm
	.type	_Z5vfreePvm, @function
_Z5vfreePvm:
.LFB26:
	.loc 1 220 0
	.cfi_startproc
.LVL81:
	.loc 1 220 0
	movl	8(%esp), %edx
	movl	4(%esp), %eax
	.loc 1 223 0
	testl	%edx, %edx
	je	.L77
	testl	%eax, %eax
	je	.L77
.LVL82:
.LBB189:
.LBB190:
	jmp	_Z7kmunmapPvm.part.0
.LVL83:
	.align 16
.L77:
	rep ret
.LBE190:
.LBE189:
	.cfi_endproc
.LFE26:
	.size	_Z5vfreePvm, .-_Z5vfreePvm
	.section	.text.unlikely
.LCOLDE10:
	.text
.LHOTE10:
	.section	.text.unlikely
.LCOLDB11:
	.text
.LHOTB11:
	.align 16
	.globl	_Z10map_kernelv
	.type	_Z10map_kernelv, @function
_Z10map_kernelv:
.LFB27:
	.loc 1 229 0
	.cfi_startproc
	pushl	%ebx
	.cfi_def_cfa_offset 8
	.cfi_offset 3, -8
	subl	$20, %esp
	.cfi_def_cfa_offset 28
	.loc 1 230 0
	pushl	$1
	.cfi_def_cfa_offset 32
	call	_Z7vmallocm
.LVL84:
	addl	$16, %esp
	.cfi_def_cfa_offset 16
.LBB191:
	.loc 1 232 0
	xorl	%edx, %edx
.LVL85:
	.align 16
.L80:
.LBB192:
	.loc 1 237 0 discriminator 2
	movl	%edx, %ecx
	movl	%edx, %ebx
.LBE192:
	.loc 1 232 0 discriminator 2
	addl	$4096, %edx
.LVL86:
.LBB193:
	.loc 1 237 0 discriminator 2
	sall	$10, %ecx
.LVL87:
	orl	$1, %ebx
.LVL88:
	shrl	$22, %ecx
.LBE193:
	.loc 1 232 0 discriminator 2
	cmpl	$4194304, %edx
.LBB194:
	.loc 1 237 0 discriminator 2
	movl	%ebx, (%eax,%ecx,4)
.LVL89:
.LBE194:
	.loc 1 232 0 discriminator 2
	jne	.L80
.LBE191:
.LBB195:
.LBB196:
	.loc 1 84 0
	movl	_cur_directory, %ecx
.LBE196:
.LBE195:
	.loc 1 240 0
	testl	%ecx, %ecx
	je	.L84
.LVL90:
.LBB197:
.LBB198:
	.loc 2 110 0
	movl	2048(%ecx), %edx
.LVL91:
	andl	$-2147479553, %edx
	orl	$3, %edx
	orl	%edx, %eax
.LVL92:
	movl	%eax, 2048(%ecx)
.LVL93:
.LBE198:
.LBE197:
	.loc 1 246 0
	addl	$8, %esp
	.cfi_remember_state
	.cfi_def_cfa_offset 8
	popl	%ebx
	.cfi_restore 3
	.cfi_def_cfa_offset 4
	ret
.LVL94:
.L84:
	.cfi_restore_state
	.loc 1 241 0
	call	abort
.LVL95:
	.cfi_endproc
.LFE27:
	.size	_Z10map_kernelv, .-_Z10map_kernelv
	.section	.text.unlikely
.LCOLDE11:
	.text
.LHOTE11:
	.globl	_cur_directory
	.section	.bss
	.align 4
	.type	_cur_directory, @object
	.size	_cur_directory, 4
_cur_directory:
	.zero	4
	.text
.Letext0:
	.section	.text.unlikely
.Letext_cold0:
	.file 3 "/home/pfalcato/i686-elf/lib/gcc/i686-elf/5.3.0/include/stdint-gcc.h"
	.file 4 "include/kernel/pmm.h"
	.file 5 "/home/pfalcato/Spartix/sysroot/usr/include/stdio.h"
	.file 6 "include/kernel/panic.h"
	.file 7 "/home/pfalcato/Spartix/sysroot/usr/include/stdlib.h"
	.section	.debug_info,"",@progbits
.Ldebug_info0:
	.long	0xae2
	.value	0x4
	.long	.Ldebug_abbrev0
	.byte	0x4
	.uleb128 0x1
	.long	.LASF79
	.byte	0x4
	.long	.LASF80
	.long	.LASF81
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
	.byte	0x3
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
	.byte	0x56
	.long	0x5a
	.uleb128 0x2
	.byte	0xc
	.byte	0x4
	.long	.LASF11
	.uleb128 0x5
	.long	.LASF82
	.uleb128 0x6
	.string	"PMM"
	.byte	0x4
	.byte	0xb
	.uleb128 0x3
	.long	.LASF12
	.byte	0x2
	.byte	0x14
	.long	0x4f
	.uleb128 0x7
	.string	"VMM"
	.byte	0x2
	.byte	0x16
	.long	0x116
	.uleb128 0x8
	.long	.LASF13
	.value	0x1000
	.byte	0x2
	.byte	0x45
	.long	0xc4
	.uleb128 0x9
	.long	.LASF15
	.byte	0x2
	.byte	0x47
	.long	0x116
	.byte	0
	.byte	0
	.uleb128 0x8
	.long	.LASF14
	.value	0x1000
	.byte	0x2
	.byte	0x4c
	.long	0xde
	.uleb128 0x9
	.long	.LASF15
	.byte	0x2
	.byte	0x4e
	.long	0x116
	.byte	0
	.byte	0
	.uleb128 0x3
	.long	.LASF16
	.byte	0x2
	.byte	0x30
	.long	0x4f
	.uleb128 0x3
	.long	.LASF14
	.byte	0x2
	.byte	0x4f
	.long	0xc4
	.uleb128 0x3
	.long	.LASF17
	.byte	0x2
	.byte	0x2f
	.long	0x4f
	.uleb128 0x3
	.long	.LASF13
	.byte	0x2
	.byte	0x48
	.long	0xaa
	.uleb128 0xa
	.long	.LASF83
	.byte	0x1
	.byte	0x58
	.long	.LASF84
	.byte	0
	.uleb128 0xb
	.long	0x5a
	.long	0x127
	.uleb128 0xc
	.long	0x127
	.value	0x3ff
	.byte	0
	.uleb128 0x2
	.byte	0x4
	.byte	0x7
	.long	.LASF18
	.uleb128 0xd
	.long	.LASF19
	.byte	0x2
	.byte	0x53
	.long	.LASF21
	.byte	0x3
	.long	0x154
	.uleb128 0xe
	.string	"pt"
	.byte	0x2
	.byte	0x53
	.long	0x154
	.uleb128 0xe
	.string	"bit"
	.byte	0x2
	.byte	0x53
	.long	0x4f
	.byte	0
	.uleb128 0xf
	.byte	0x4
	.long	0xde
	.uleb128 0xd
	.long	.LASF20
	.byte	0x2
	.byte	0x5b
	.long	.LASF22
	.byte	0x3
	.long	0x180
	.uleb128 0xe
	.string	"pt"
	.byte	0x2
	.byte	0x5b
	.long	0x154
	.uleb128 0x10
	.long	.LASF23
	.byte	0x2
	.byte	0x5b
	.long	0x76
	.byte	0
	.uleb128 0x11
	.long	.LASF26
	.byte	0x2
	.byte	0x68
	.long	.LASF28
	.long	0x76
	.byte	0x3
	.long	0x19f
	.uleb128 0xe
	.string	"pt"
	.byte	0x2
	.byte	0x68
	.long	0xde
	.byte	0
	.uleb128 0xd
	.long	.LASF24
	.byte	0x2
	.byte	0x57
	.long	.LASF25
	.byte	0x3
	.long	0x1c5
	.uleb128 0xe
	.string	"pt"
	.byte	0x2
	.byte	0x57
	.long	0x154
	.uleb128 0xe
	.string	"bit"
	.byte	0x2
	.byte	0x57
	.long	0x4f
	.byte	0
	.uleb128 0x11
	.long	.LASF27
	.byte	0x1
	.byte	0x49
	.long	.LASF29
	.long	0x68
	.byte	0x1
	.long	0x1e5
	.uleb128 0xe
	.string	"dir"
	.byte	0x1
	.byte	0x49
	.long	0x1e5
	.byte	0
	.uleb128 0xf
	.byte	0x4
	.long	0xe9
	.uleb128 0xd
	.long	.LASF30
	.byte	0x2
	.byte	0x74
	.long	.LASF31
	.byte	0x3
	.long	0x211
	.uleb128 0xe
	.string	"pd"
	.byte	0x2
	.byte	0x74
	.long	0x211
	.uleb128 0x10
	.long	.LASF32
	.byte	0x2
	.byte	0x74
	.long	0x76
	.byte	0
	.uleb128 0xf
	.byte	0x4
	.long	0xf4
	.uleb128 0xd
	.long	.LASF33
	.byte	0x2
	.byte	0x6c
	.long	.LASF34
	.byte	0x3
	.long	0x23d
	.uleb128 0xe
	.string	"pd"
	.byte	0x2
	.byte	0x6c
	.long	0x211
	.uleb128 0xe
	.string	"bit"
	.byte	0x2
	.byte	0x6c
	.long	0x4f
	.byte	0
	.uleb128 0x11
	.long	.LASF35
	.byte	0x1
	.byte	0x52
	.long	.LASF36
	.long	0x1e5
	.byte	0x1
	.long	0x25d
	.uleb128 0x12
	.string	"ret"
	.byte	0x1
	.byte	0x54
	.long	0x25d
	.byte	0
	.uleb128 0x13
	.byte	0x4
	.uleb128 0x11
	.long	.LASF37
	.byte	0x2
	.byte	0x80
	.long	.LASF38
	.long	0x27e
	.byte	0x3
	.long	0x27e
	.uleb128 0xe
	.string	"pd"
	.byte	0x2
	.byte	0x80
	.long	0xf4
	.byte	0
	.uleb128 0x2
	.byte	0x1
	.byte	0x2
	.long	.LASF39
	.uleb128 0x11
	.long	.LASF40
	.byte	0x2
	.byte	0x84
	.long	.LASF41
	.long	0x76
	.byte	0x3
	.long	0x2a4
	.uleb128 0xe
	.string	"pd"
	.byte	0x2
	.byte	0x84
	.long	0xf4
	.byte	0
	.uleb128 0x11
	.long	.LASF42
	.byte	0x2
	.byte	0x78
	.long	.LASF43
	.long	0x27e
	.byte	0x3
	.long	0x2c3
	.uleb128 0xe
	.string	"pd"
	.byte	0x2
	.byte	0x78
	.long	0xf4
	.byte	0
	.uleb128 0x14
	.long	.LASF85
	.byte	0x1
	.byte	0x29
	.long	0x68
	.byte	0x1
	.long	0x2e7
	.uleb128 0xe
	.string	"pt"
	.byte	0x1
	.byte	0x29
	.long	0x154
	.uleb128 0x12
	.string	"p"
	.byte	0x1
	.byte	0x2b
	.long	0x25d
	.byte	0
	.uleb128 0x11
	.long	.LASF44
	.byte	0x2
	.byte	0x5f
	.long	.LASF45
	.long	0x68
	.byte	0x3
	.long	0x306
	.uleb128 0xe
	.string	"pt"
	.byte	0x2
	.byte	0x5f
	.long	0xde
	.byte	0
	.uleb128 0xd
	.long	.LASF46
	.byte	0x2
	.byte	0x90
	.long	.LASF47
	.byte	0x3
	.long	0x322
	.uleb128 0x10
	.long	.LASF48
	.byte	0x2
	.byte	0x90
	.long	0x5a
	.byte	0
	.uleb128 0x15
	.long	.LASF86
	.byte	0x1
	.byte	0x33
	.byte	0x1
	.long	0x342
	.uleb128 0xe
	.string	"pt"
	.byte	0x1
	.byte	0x33
	.long	0x154
	.uleb128 0x12
	.string	"p"
	.byte	0x1
	.byte	0x35
	.long	0x25d
	.byte	0
	.uleb128 0xd
	.long	.LASF49
	.byte	0x1
	.byte	0xb7
	.long	.LASF50
	.byte	0x1
	.long	0x3ac
	.uleb128 0x10
	.long	.LASF51
	.byte	0x1
	.byte	0xb7
	.long	0x25d
	.uleb128 0x10
	.long	.LASF52
	.byte	0x1
	.byte	0xb7
	.long	0x94
	.uleb128 0x16
	.long	.LASF53
	.byte	0x1
	.byte	0xbd
	.long	0x1e5
	.uleb128 0x16
	.long	.LASF54
	.byte	0x1
	.byte	0xc0
	.long	0x211
	.uleb128 0x12
	.string	"pt"
	.byte	0x1
	.byte	0xc3
	.long	0x3ac
	.uleb128 0x17
	.uleb128 0x12
	.string	"i"
	.byte	0x1
	.byte	0xc6
	.long	0x94
	.uleb128 0x16
	.long	.LASF55
	.byte	0x1
	.byte	0xc6
	.long	0x94
	.uleb128 0x17
	.uleb128 0x16
	.long	.LASF56
	.byte	0x1
	.byte	0xc8
	.long	0x154
	.byte	0
	.byte	0
	.byte	0
	.uleb128 0xf
	.byte	0x4
	.long	0xff
	.uleb128 0x18
	.long	0x342
	.long	.LFB28
	.long	.LFE28-.LFB28
	.uleb128 0x1
	.byte	0x9c
	.long	0x4b7
	.uleb128 0x19
	.long	0x352
	.long	.LLST0
	.uleb128 0x19
	.long	0x35d
	.long	.LLST1
	.uleb128 0x1a
	.long	0x368
	.uleb128 0x1
	.byte	0x51
	.uleb128 0x1b
	.long	0x373
	.long	.LLST2
	.uleb128 0x1b
	.long	0x37e
	.long	.LLST3
	.uleb128 0x1c
	.long	0x23d
	.long	.LBB136
	.long	.LBE136-.LBB136
	.byte	0x1
	.byte	0xbd
	.long	0x413
	.uleb128 0x1d
	.long	.LBB137
	.long	.LBE137-.LBB137
	.uleb128 0x1e
	.long	0x251
	.byte	0
	.byte	0
	.uleb128 0x1d
	.long	.LBB138
	.long	.LBE138-.LBB138
	.uleb128 0x1b
	.long	0x389
	.long	.LLST4
	.uleb128 0x1b
	.long	0x392
	.long	.LLST5
	.uleb128 0x1d
	.long	.LBB139
	.long	.LBE139-.LBB139
	.uleb128 0x1b
	.long	0x39e
	.long	.LLST6
	.uleb128 0x1f
	.long	0x322
	.long	.LBB140
	.long	.Ldebug_ranges0+0
	.byte	0x1
	.byte	0xc9
	.long	0x49b
	.uleb128 0x19
	.long	0x32e
	.long	.LLST7
	.uleb128 0x20
	.long	.Ldebug_ranges0+0
	.uleb128 0x1b
	.long	0x338
	.long	.LLST8
	.uleb128 0x1c
	.long	0x19f
	.long	.LBB142
	.long	.LBE142-.LBB142
	.byte	0x1
	.byte	0x39
	.long	0x490
	.uleb128 0x19
	.long	0x1b9
	.long	.LLST9
	.uleb128 0x19
	.long	0x1af
	.long	.LLST10
	.byte	0
	.uleb128 0x21
	.long	.LVL9
	.long	0xa97
	.byte	0
	.byte	0
	.uleb128 0x22
	.long	0x306
	.long	.LBB148
	.long	.LBE148-.LBB148
	.byte	0x1
	.byte	0xca
	.uleb128 0x19
	.long	0x316
	.long	.LLST11
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.uleb128 0x23
	.long	0x1c5
	.long	.LASF29
	.long	.LFB20
	.long	.LFE20-.LFB20
	.uleb128 0x1
	.byte	0x9c
	.long	0x4e0
	.uleb128 0x24
	.long	0x1d9
	.uleb128 0x2
	.byte	0x91
	.sleb128 0
	.uleb128 0x21
	.long	.LVL17
	.long	0xaa6
	.byte	0
	.uleb128 0x23
	.long	0x23d
	.long	.LASF36
	.long	.LFB21
	.long	.LFE21-.LFB21
	.uleb128 0x1
	.byte	0x9c
	.long	0x503
	.uleb128 0x1a
	.long	0x251
	.uleb128 0x5
	.byte	0x3
	.long	_cur_directory
	.byte	0
	.uleb128 0x25
	.long	0x10a
	.long	.LFB22
	.long	.LFE22-.LFB22
	.uleb128 0x1
	.byte	0x9c
	.long	0x69b
	.uleb128 0x26
	.string	"mb"
	.byte	0x1
	.byte	0x5a
	.long	0x3ac
	.long	.LLST12
	.uleb128 0x27
	.long	.LASF57
	.byte	0x1
	.byte	0x5c
	.long	0x3ac
	.long	.LLST13
	.uleb128 0x26
	.string	"dir"
	.byte	0x1
	.byte	0x71
	.long	0x1e5
	.long	.LLST14
	.uleb128 0x28
	.long	.LASF54
	.byte	0x1
	.byte	0x73
	.long	0x211
	.sleb128 -2143344640
	.uleb128 0x28
	.long	.LASF58
	.byte	0x1
	.byte	0x79
	.long	0x211
	.sleb128 -2143346688
	.uleb128 0x28
	.long	.LASF59
	.byte	0x1
	.byte	0x7f
	.long	0x211
	.sleb128 -2143342596
	.uleb128 0x29
	.long	.LBB150
	.long	.LBE150-.LBB150
	.long	0x5bc
	.uleb128 0x12
	.string	"i"
	.byte	0x1
	.byte	0x5f
	.long	0x68
	.uleb128 0x27
	.long	.LASF60
	.byte	0x1
	.byte	0x5f
	.long	0x68
	.long	.LLST15
	.uleb128 0x27
	.long	.LASF51
	.byte	0x1
	.byte	0x5f
	.long	0x68
	.long	.LLST15
	.uleb128 0x20
	.long	.Ldebug_ranges0+0x20
	.uleb128 0x27
	.long	.LASF56
	.byte	0x1
	.byte	0x61
	.long	0xde
	.long	.LLST17
	.byte	0
	.byte	0
	.uleb128 0x29
	.long	.LBB154
	.long	.LBE154-.LBB154
	.long	0x606
	.uleb128 0x12
	.string	"i"
	.byte	0x1
	.byte	0x68
	.long	0x68
	.uleb128 0x27
	.long	.LASF60
	.byte	0x1
	.byte	0x68
	.long	0x68
	.long	.LLST18
	.uleb128 0x27
	.long	.LASF51
	.byte	0x1
	.byte	0x68
	.long	0x68
	.long	.LLST19
	.uleb128 0x20
	.long	.Ldebug_ranges0+0x40
	.uleb128 0x27
	.long	.LASF56
	.byte	0x1
	.byte	0x6a
	.long	0xde
	.long	.LLST20
	.byte	0
	.byte	0
	.uleb128 0x1f
	.long	0x1c5
	.long	.LBB158
	.long	.Ldebug_ranges0+0x60
	.byte	0x1
	.byte	0x84
	.long	0x62c
	.uleb128 0x19
	.long	0x1d9
	.long	.LLST21
	.uleb128 0x21
	.long	.LVL37
	.long	0xaa6
	.byte	0
	.uleb128 0x1c
	.long	0x1eb
	.long	.LBB161
	.long	.LBE161-.LBB161
	.byte	0x1
	.byte	0x78
	.long	0x652
	.uleb128 0x19
	.long	0x205
	.long	.LLST22
	.uleb128 0x19
	.long	0x1fb
	.long	.LLST23
	.byte	0
	.uleb128 0x1c
	.long	0x1eb
	.long	.LBB163
	.long	.LBE163-.LBB163
	.byte	0x1
	.byte	0x7e
	.long	0x678
	.uleb128 0x19
	.long	0x205
	.long	.LLST24
	.uleb128 0x19
	.long	0x1fb
	.long	.LLST25
	.byte	0
	.uleb128 0x22
	.long	0x1eb
	.long	.LBB165
	.long	.LBE165-.LBB165
	.byte	0x1
	.byte	0x83
	.uleb128 0x19
	.long	0x205
	.long	.LLST26
	.uleb128 0x19
	.long	0x1fb
	.long	.LLST27
	.byte	0
	.byte	0
	.uleb128 0x2a
	.long	.LASF62
	.byte	0x1
	.byte	0x86
	.long	.LASF64
	.long	0x25d
	.long	.LFB23
	.long	.LFE23-.LFB23
	.uleb128 0x1
	.byte	0x9c
	.long	0x867
	.uleb128 0x2b
	.long	.LASF51
	.byte	0x1
	.byte	0x86
	.long	0x4f
	.uleb128 0x2
	.byte	0x91
	.sleb128 0
	.uleb128 0x2c
	.long	.LASF52
	.byte	0x1
	.byte	0x86
	.long	0x94
	.long	.LLST28
	.uleb128 0x2d
	.long	.LASF53
	.byte	0x1
	.byte	0x8a
	.long	0x1e5
	.uleb128 0x1
	.byte	0x52
	.uleb128 0x27
	.long	.LASF54
	.byte	0x1
	.byte	0x8f
	.long	0x211
	.long	.LLST29
	.uleb128 0x26
	.string	"pt"
	.byte	0x1
	.byte	0x90
	.long	0x3ac
	.long	.LLST30
	.uleb128 0x27
	.long	.LASF61
	.byte	0x1
	.byte	0xa7
	.long	0x4f
	.long	.LLST31
	.uleb128 0x1c
	.long	0x23d
	.long	.LBB168
	.long	.LBE168-.LBB168
	.byte	0x1
	.byte	0x8a
	.long	0x731
	.uleb128 0x1d
	.long	.LBB169
	.long	.LBE169-.LBB169
	.uleb128 0x1e
	.long	0x251
	.byte	0
	.byte	0
	.uleb128 0x29
	.long	.LBB171
	.long	.LBE171-.LBB171
	.long	0x79f
	.uleb128 0x26
	.string	"ptr"
	.byte	0x1
	.byte	0x98
	.long	0x25d
	.long	.LLST32
	.uleb128 0x1c
	.long	0x217
	.long	.LBB172
	.long	.LBE172-.LBB172
	.byte	0x1
	.byte	0x97
	.long	0x773
	.uleb128 0x19
	.long	0x231
	.long	.LLST33
	.uleb128 0x19
	.long	0x227
	.long	.LLST34
	.byte	0
	.uleb128 0x1f
	.long	0x1eb
	.long	.LBB174
	.long	.Ldebug_ranges0+0x78
	.byte	0x1
	.byte	0x99
	.long	0x795
	.uleb128 0x19
	.long	0x205
	.long	.LLST35
	.uleb128 0x2e
	.long	0x1fb
	.byte	0
	.uleb128 0x21
	.long	.LVL67
	.long	0xab1
	.byte	0
	.uleb128 0x29
	.long	.LBB178
	.long	.LBE178-.LBB178
	.long	0x829
	.uleb128 0x26
	.string	"i"
	.byte	0x1
	.byte	0xa8
	.long	0x68
	.long	.LLST36
	.uleb128 0x27
	.long	.LASF55
	.byte	0x1
	.byte	0xa8
	.long	0x68
	.long	.LLST37
	.uleb128 0x20
	.long	.Ldebug_ranges0+0x90
	.uleb128 0x27
	.long	.LASF56
	.byte	0x1
	.byte	0xac
	.long	0xde
	.long	.LLST38
	.uleb128 0x1c
	.long	0x2c3
	.long	.LBB180
	.long	.LBE180-.LBB180
	.byte	0x1
	.byte	0xad
	.long	0x815
	.uleb128 0x19
	.long	0x2d3
	.long	.LLST39
	.uleb128 0x1d
	.long	.LBB181
	.long	.LBE181-.LBB181
	.uleb128 0x1b
	.long	0x2dd
	.long	.LLST40
	.uleb128 0x21
	.long	.LVL51
	.long	0xab1
	.byte	0
	.byte	0
	.uleb128 0x21
	.long	.LVL53
	.long	0xac0
	.uleb128 0x21
	.long	.LVL54
	.long	0xacb
	.byte	0
	.byte	0
	.uleb128 0x1c
	.long	0x1eb
	.long	.LBB186
	.long	.LBE186-.LBB186
	.byte	0x1
	.byte	0xa5
	.long	0x84b
	.uleb128 0x19
	.long	0x205
	.long	.LLST41
	.uleb128 0x2e
	.long	0x1fb
	.byte	0
	.uleb128 0x21
	.long	.LVL59
	.long	0xab1
	.uleb128 0x21
	.long	.LVL70
	.long	0xacb
	.uleb128 0x21
	.long	.LVL71
	.long	0xada
	.byte	0
	.uleb128 0x23
	.long	0x342
	.long	.LASF50
	.long	.LFB24
	.long	.LFE24-.LFB24
	.uleb128 0x1
	.byte	0x9c
	.long	0x8b8
	.uleb128 0x19
	.long	0x352
	.long	.LLST42
	.uleb128 0x19
	.long	0x35d
	.long	.LLST43
	.uleb128 0x1e
	.long	0x368
	.uleb128 0x1e
	.long	0x373
	.uleb128 0x1e
	.long	0x37e
	.uleb128 0x2f
	.long	.LVL73
	.long	0x3b2
	.uleb128 0x30
	.uleb128 0x1
	.byte	0x50
	.uleb128 0x3
	.byte	0x91
	.sleb128 0
	.byte	0x6
	.uleb128 0x30
	.uleb128 0x1
	.byte	0x52
	.uleb128 0x3
	.byte	0x91
	.sleb128 4
	.byte	0x6
	.byte	0
	.byte	0
	.uleb128 0x2a
	.long	.LASF63
	.byte	0x1
	.byte	0xce
	.long	.LASF65
	.long	0x25d
	.long	.LFB25
	.long	.LFE25-.LFB25
	.uleb128 0x1
	.byte	0x9c
	.long	0x90e
	.uleb128 0x2b
	.long	.LASF52
	.byte	0x1
	.byte	0xce
	.long	0x94
	.uleb128 0x2
	.byte	0x91
	.sleb128 0
	.uleb128 0x26
	.string	"ptr"
	.byte	0x1
	.byte	0xd2
	.long	0x25d
	.long	.LLST44
	.uleb128 0x21
	.long	.LVL75
	.long	0xab1
	.uleb128 0x21
	.long	.LVL77
	.long	0xa97
	.uleb128 0x21
	.long	.LVL78
	.long	0x69b
	.byte	0
	.uleb128 0x31
	.long	.LASF66
	.byte	0x1
	.byte	0xdb
	.long	.LASF68
	.long	.LFB26
	.long	.LFE26-.LFB26
	.uleb128 0x1
	.byte	0x9c
	.long	0x999
	.uleb128 0x32
	.string	"ptr"
	.byte	0x1
	.byte	0xdb
	.long	0x25d
	.long	.LLST45
	.uleb128 0x2c
	.long	.LASF52
	.byte	0x1
	.byte	0xdb
	.long	0x94
	.long	.LLST46
	.uleb128 0x22
	.long	0x342
	.long	.LBB189
	.long	.LBE189-.LBB189
	.byte	0x1
	.byte	0xe1
	.uleb128 0x19
	.long	0x35d
	.long	.LLST47
	.uleb128 0x19
	.long	0x352
	.long	.LLST48
	.uleb128 0x1d
	.long	.LBB190
	.long	.LBE190-.LBB190
	.uleb128 0x1e
	.long	0x368
	.uleb128 0x1e
	.long	0x373
	.uleb128 0x1e
	.long	0x37e
	.uleb128 0x2f
	.long	.LVL83
	.long	0x3b2
	.uleb128 0x30
	.uleb128 0x1
	.byte	0x50
	.uleb128 0x3
	.byte	0x91
	.sleb128 0
	.byte	0x6
	.uleb128 0x30
	.uleb128 0x1
	.byte	0x52
	.uleb128 0x3
	.byte	0x91
	.sleb128 4
	.byte	0x6
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.uleb128 0x31
	.long	.LASF67
	.byte	0x1
	.byte	0xe4
	.long	.LASF69
	.long	.LFB27
	.long	.LFE27-.LFB27
	.uleb128 0x1
	.byte	0x9c
	.long	0xa86
	.uleb128 0x27
	.long	.LASF57
	.byte	0x1
	.byte	0xe6
	.long	0x3ac
	.long	.LLST49
	.uleb128 0x33
	.string	"pd"
	.byte	0x1
	.byte	0xef
	.long	0x1e5
	.uleb128 0x1
	.byte	0x51
	.uleb128 0x27
	.long	.LASF54
	.byte	0x1
	.byte	0xf2
	.long	0x211
	.long	.LLST50
	.uleb128 0x29
	.long	.LBB191
	.long	.LBE191-.LBB191
	.long	0xa2a
	.uleb128 0x26
	.string	"i"
	.byte	0x1
	.byte	0xe8
	.long	0x68
	.long	.LLST51
	.uleb128 0x27
	.long	.LASF60
	.byte	0x1
	.byte	0xe8
	.long	0x68
	.long	.LLST52
	.uleb128 0x27
	.long	.LASF51
	.byte	0x1
	.byte	0xe8
	.long	0x68
	.long	.LLST53
	.uleb128 0x20
	.long	.Ldebug_ranges0+0xc0
	.uleb128 0x27
	.long	.LASF56
	.byte	0x1
	.byte	0xea
	.long	0xde
	.long	.LLST54
	.byte	0
	.byte	0
	.uleb128 0x1c
	.long	0x23d
	.long	.LBB195
	.long	.LBE195-.LBB195
	.byte	0x1
	.byte	0xef
	.long	0xa4d
	.uleb128 0x1d
	.long	.LBB196
	.long	.LBE196-.LBB196
	.uleb128 0x1e
	.long	0x251
	.byte	0
	.byte	0
	.uleb128 0x1c
	.long	0x217
	.long	.LBB197
	.long	.LBE197-.LBB197
	.byte	0x1
	.byte	0xf5
	.long	0xa73
	.uleb128 0x19
	.long	0x231
	.long	.LLST55
	.uleb128 0x19
	.long	0x227
	.long	.LLST56
	.byte	0
	.uleb128 0x21
	.long	.LVL84
	.long	0x8b8
	.uleb128 0x21
	.long	.LVL95
	.long	0xada
	.byte	0
	.uleb128 0x34
	.long	.LASF87
	.byte	0x1
	.byte	0x47
	.long	0x1e5
	.uleb128 0x5
	.byte	0x3
	.long	_cur_directory
	.uleb128 0x35
	.long	.LASF70
	.long	.LASF72
	.byte	0x4
	.byte	0x1b
	.long	.LASF70
	.uleb128 0x36
	.long	.LASF74
	.long	.LASF74
	.byte	0x1
	.byte	0x26
	.uleb128 0x35
	.long	.LASF71
	.long	.LASF73
	.byte	0x4
	.byte	0x1a
	.long	.LASF71
	.uleb128 0x36
	.long	.LASF75
	.long	.LASF75
	.byte	0x5
	.byte	0x18
	.uleb128 0x35
	.long	.LASF76
	.long	.LASF77
	.byte	0x6
	.byte	0x1a
	.long	.LASF76
	.uleb128 0x36
	.long	.LASF78
	.long	.LASF78
	.byte	0x7
	.byte	0x20
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
	.uleb128 0x8
	.uleb128 0x13
	.byte	0x1
	.uleb128 0x3
	.uleb128 0xe
	.uleb128 0xb
	.uleb128 0x5
	.uleb128 0x3a
	.uleb128 0xb
	.uleb128 0x3b
	.uleb128 0xb
	.uleb128 0x1
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0x9
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
	.uleb128 0xa
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
	.uleb128 0xb
	.uleb128 0x1
	.byte	0x1
	.uleb128 0x49
	.uleb128 0x13
	.uleb128 0x1
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0xc
	.uleb128 0x21
	.byte	0
	.uleb128 0x49
	.uleb128 0x13
	.uleb128 0x2f
	.uleb128 0x5
	.byte	0
	.byte	0
	.uleb128 0xd
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
	.uleb128 0xe
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
	.uleb128 0xf
	.uleb128 0xf
	.byte	0
	.uleb128 0xb
	.uleb128 0xb
	.uleb128 0x49
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0x10
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
	.uleb128 0x11
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
	.uleb128 0x20
	.uleb128 0xb
	.uleb128 0x1
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0x12
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
	.uleb128 0x13
	.uleb128 0xf
	.byte	0
	.uleb128 0xb
	.uleb128 0xb
	.byte	0
	.byte	0
	.uleb128 0x14
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
	.uleb128 0x15
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
	.uleb128 0x16
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
	.uleb128 0x17
	.uleb128 0xb
	.byte	0x1
	.byte	0
	.byte	0
	.uleb128 0x18
	.uleb128 0x2e
	.byte	0x1
	.uleb128 0x31
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
	.uleb128 0x5
	.byte	0
	.uleb128 0x31
	.uleb128 0x13
	.uleb128 0x2
	.uleb128 0x17
	.byte	0
	.byte	0
	.uleb128 0x1a
	.uleb128 0x34
	.byte	0
	.uleb128 0x31
	.uleb128 0x13
	.uleb128 0x2
	.uleb128 0x18
	.byte	0
	.byte	0
	.uleb128 0x1b
	.uleb128 0x34
	.byte	0
	.uleb128 0x31
	.uleb128 0x13
	.uleb128 0x2
	.uleb128 0x17
	.byte	0
	.byte	0
	.uleb128 0x1c
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
	.uleb128 0x1d
	.uleb128 0xb
	.byte	0x1
	.uleb128 0x11
	.uleb128 0x1
	.uleb128 0x12
	.uleb128 0x6
	.byte	0
	.byte	0
	.uleb128 0x1e
	.uleb128 0x34
	.byte	0
	.uleb128 0x31
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0x1f
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
	.uleb128 0x20
	.uleb128 0xb
	.byte	0x1
	.uleb128 0x55
	.uleb128 0x17
	.byte	0
	.byte	0
	.uleb128 0x21
	.uleb128 0x4109
	.byte	0
	.uleb128 0x11
	.uleb128 0x1
	.uleb128 0x31
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0x22
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
	.uleb128 0x23
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
	.uleb128 0x24
	.uleb128 0x5
	.byte	0
	.uleb128 0x31
	.uleb128 0x13
	.uleb128 0x2
	.uleb128 0x18
	.byte	0
	.byte	0
	.uleb128 0x25
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
	.uleb128 0x26
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
	.uleb128 0x27
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
	.uleb128 0xd
	.byte	0
	.byte	0
	.uleb128 0x29
	.uleb128 0xb
	.byte	0x1
	.uleb128 0x11
	.uleb128 0x1
	.uleb128 0x12
	.uleb128 0x6
	.uleb128 0x1
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0x2a
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
	.uleb128 0x2b
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
	.uleb128 0x2c
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
	.uleb128 0x2d
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
	.uleb128 0x2e
	.uleb128 0x5
	.byte	0
	.uleb128 0x31
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0x2f
	.uleb128 0x4109
	.byte	0x1
	.uleb128 0x11
	.uleb128 0x1
	.uleb128 0x2115
	.uleb128 0x19
	.uleb128 0x31
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0x30
	.uleb128 0x410a
	.byte	0
	.uleb128 0x2
	.uleb128 0x18
	.uleb128 0x2111
	.uleb128 0x18
	.byte	0
	.byte	0
	.uleb128 0x31
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
	.uleb128 0x32
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
	.uleb128 0x33
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
	.uleb128 0x18
	.byte	0
	.byte	0
	.uleb128 0x34
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
	.uleb128 0x35
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
	.uleb128 0x36
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
	.long	.LVL2-.Ltext0
	.value	0x1
	.byte	0x50
	.long	.LVL2-.Ltext0
	.long	.LVL6-.Ltext0
	.value	0x1
	.byte	0x53
	.long	.LVL6-.Ltext0
	.long	.LFE28-.Ltext0
	.value	0x4
	.byte	0xf3
	.uleb128 0x1
	.byte	0x50
	.byte	0x9f
	.long	0
	.long	0
.LLST1:
	.long	.LVL0-.Ltext0
	.long	.LVL6-.Ltext0
	.value	0x1
	.byte	0x52
	.long	.LVL6-.Ltext0
	.long	.LVL15-.Ltext0
	.value	0x2
	.byte	0x91
	.sleb128 -36
	.long	.LVL15-.Ltext0
	.long	.LFE28-.Ltext0
	.value	0x4
	.byte	0xf3
	.uleb128 0x1
	.byte	0x52
	.byte	0x9f
	.long	0
	.long	0
.LLST2:
	.long	.LVL1-.Ltext0
	.long	.LVL2-.Ltext0
	.value	0xa
	.byte	0x70
	.sleb128 0
	.byte	0x46
	.byte	0x25
	.byte	0x32
	.byte	0x24
	.byte	0x71
	.sleb128 0
	.byte	0x22
	.byte	0x9f
	.long	.LVL2-.Ltext0
	.long	.LVL4-.Ltext0
	.value	0xa
	.byte	0x73
	.sleb128 0
	.byte	0x46
	.byte	0x25
	.byte	0x32
	.byte	0x24
	.byte	0x71
	.sleb128 0
	.byte	0x22
	.byte	0x9f
	.long	.LVL4-.Ltext0
	.long	.LVL6-.Ltext0
	.value	0xe
	.byte	0x73
	.sleb128 0
	.byte	0x46
	.byte	0x25
	.byte	0x32
	.byte	0x24
	.byte	0x3
	.long	_cur_directory
	.byte	0x6
	.byte	0x22
	.byte	0x9f
	.long	0
	.long	0
.LLST3:
	.long	.LVL3-.Ltext0
	.long	.LVL15-.Ltext0
	.value	0x1
	.byte	0x57
	.long	0
	.long	0
.LLST4:
	.long	.LVL5-.Ltext0
	.long	.LVL6-.Ltext0
	.value	0x2
	.byte	0x30
	.byte	0x9f
	.long	.LVL6-.Ltext0
	.long	.LVL15-.Ltext0
	.value	0x1
	.byte	0x55
	.long	0
	.long	0
.LLST5:
	.long	.LVL5-.Ltext0
	.long	.LVL15-.Ltext0
	.value	0x1
	.byte	0x53
	.long	0
	.long	0
.LLST6:
	.long	.LVL6-.Ltext0
	.long	.LVL7-.Ltext0
	.value	0x8
	.byte	0x76
	.sleb128 0
	.byte	0x32
	.byte	0x24
	.byte	0x77
	.sleb128 0
	.byte	0x22
	.byte	0x9f
	.long	.LVL8-.Ltext0
	.long	.LVL9-1-.Ltext0
	.value	0x8
	.byte	0x70
	.sleb128 0
	.byte	0x32
	.byte	0x24
	.byte	0x77
	.sleb128 0
	.byte	0x22
	.byte	0x9f
	.long	.LVL9-1-.Ltext0
	.long	.LVL15-.Ltext0
	.value	0x8
	.byte	0x76
	.sleb128 0
	.byte	0x32
	.byte	0x24
	.byte	0x77
	.sleb128 0
	.byte	0x22
	.byte	0x9f
	.long	0
	.long	0
.LLST7:
	.long	.LVL8-.Ltext0
	.long	.LVL9-1-.Ltext0
	.value	0x8
	.byte	0x70
	.sleb128 0
	.byte	0x32
	.byte	0x24
	.byte	0x77
	.sleb128 0
	.byte	0x22
	.byte	0x9f
	.long	.LVL9-1-.Ltext0
	.long	.LVL11-.Ltext0
	.value	0x8
	.byte	0x76
	.sleb128 0
	.byte	0x32
	.byte	0x24
	.byte	0x77
	.sleb128 0
	.byte	0x22
	.byte	0x9f
	.long	0
	.long	0
.LLST8:
	.long	.LVL8-.Ltext0
	.long	.LVL9-1-.Ltext0
	.value	0x1
	.byte	0x52
	.long	0
	.long	0
.LLST9:
	.long	.LVL10-.Ltext0
	.long	.LVL11-.Ltext0
	.value	0x2
	.byte	0x31
	.byte	0x9f
	.long	0
	.long	0
.LLST10:
	.long	.LVL10-.Ltext0
	.long	.LVL11-.Ltext0
	.value	0x8
	.byte	0x76
	.sleb128 0
	.byte	0x32
	.byte	0x24
	.byte	0x77
	.sleb128 0
	.byte	0x22
	.byte	0x9f
	.long	0
	.long	0
.LLST11:
	.long	.LVL11-.Ltext0
	.long	.LVL12-.Ltext0
	.value	0x1
	.byte	0x53
	.long	0
	.long	0
.LLST12:
	.long	.LVL19-.Ltext0
	.long	.LVL34-.Ltext0
	.value	0x6
	.byte	0x9e
	.uleb128 0x4
	.long	0x803f0000
	.long	.LVL34-.Ltext0
	.long	.LFE22-.Ltext0
	.value	0x6
	.byte	0xc
	.long	0x3f1000
	.byte	0x9f
	.long	0
	.long	0
.LLST13:
	.long	.LVL20-.Ltext0
	.long	.LVL33-.Ltext0
	.value	0x6
	.byte	0x9e
	.uleb128 0x4
	.long	0x803f1000
	.long	.LVL33-.Ltext0
	.long	.LFE22-.Ltext0
	.value	0x5
	.byte	0x8
	.byte	0xfc
	.byte	0x3e
	.byte	0x24
	.byte	0x9f
	.long	0
	.long	0
.LLST14:
	.long	.LVL31-.Ltext0
	.long	.LVL35-.Ltext0
	.value	0x6
	.byte	0x9e
	.uleb128 0x4
	.long	0x803f2000
	.long	.LVL35-.Ltext0
	.long	.LFE22-.Ltext0
	.value	0x6
	.byte	0xc
	.long	0x3f2000
	.byte	0x9f
	.long	0
	.long	0
.LLST15:
	.long	.LVL21-.Ltext0
	.long	.LVL22-.Ltext0
	.value	0x1
	.byte	0x50
	.long	.LVL22-.Ltext0
	.long	.LVL23-.Ltext0
	.value	0x1
	.byte	0x52
	.long	.LVL23-.Ltext0
	.long	.LVL24-.Ltext0
	.value	0x1
	.byte	0x51
	.long	.LVL24-.Ltext0
	.long	.LVL25-.Ltext0
	.value	0x4
	.byte	0x70
	.sleb128 -4096
	.byte	0x9f
	.long	.LVL25-.Ltext0
	.long	.LVL26-.Ltext0
	.value	0x1
	.byte	0x50
	.long	0
	.long	0
.LLST17:
	.long	.LVL21-.Ltext0
	.long	.LVL22-.Ltext0
	.value	0x5
	.byte	0x70
	.sleb128 0
	.byte	0x35
	.byte	0x21
	.byte	0x9f
	.long	.LVL22-.Ltext0
	.long	.LVL23-.Ltext0
	.value	0x5
	.byte	0x72
	.sleb128 0
	.byte	0x35
	.byte	0x21
	.byte	0x9f
	.long	.LVL23-.Ltext0
	.long	.LVL24-.Ltext0
	.value	0x5
	.byte	0x71
	.sleb128 0
	.byte	0x35
	.byte	0x21
	.byte	0x9f
	.long	.LVL24-.Ltext0
	.long	.LVL25-.Ltext0
	.value	0x1
	.byte	0x51
	.long	0
	.long	0
.LLST18:
	.long	.LVL26-.Ltext0
	.long	.LVL27-.Ltext0
	.value	0x1
	.byte	0x50
	.long	.LVL27-.Ltext0
	.long	.LVL28-.Ltext0
	.value	0x1
	.byte	0x52
	.long	.LVL28-.Ltext0
	.long	.LVL29-.Ltext0
	.value	0x1
	.byte	0x51
	.long	.LVL29-.Ltext0
	.long	.LVL30-.Ltext0
	.value	0x4
	.byte	0x70
	.sleb128 -4096
	.byte	0x9f
	.long	.LVL30-.Ltext0
	.long	.LVL32-.Ltext0
	.value	0x1
	.byte	0x50
	.long	0
	.long	0
.LLST19:
	.long	.LVL26-.Ltext0
	.long	.LVL27-.Ltext0
	.value	0x7
	.byte	0x70
	.sleb128 -2147483648
	.byte	0x9f
	.long	.LVL27-.Ltext0
	.long	.LVL28-.Ltext0
	.value	0x7
	.byte	0x72
	.sleb128 -2147483648
	.byte	0x9f
	.long	.LVL28-.Ltext0
	.long	.LVL29-.Ltext0
	.value	0x7
	.byte	0x71
	.sleb128 -2147483648
	.byte	0x9f
	.long	.LVL29-.Ltext0
	.long	.LVL30-.Ltext0
	.value	0x7
	.byte	0x70
	.sleb128 2147479552
	.byte	0x9f
	.long	.LVL30-.Ltext0
	.long	.LVL32-.Ltext0
	.value	0x7
	.byte	0x70
	.sleb128 -2147483648
	.byte	0x9f
	.long	0
	.long	0
.LLST20:
	.long	.LVL26-.Ltext0
	.long	.LVL27-.Ltext0
	.value	0x5
	.byte	0x70
	.sleb128 0
	.byte	0x35
	.byte	0x21
	.byte	0x9f
	.long	.LVL27-.Ltext0
	.long	.LVL28-.Ltext0
	.value	0x5
	.byte	0x72
	.sleb128 0
	.byte	0x35
	.byte	0x21
	.byte	0x9f
	.long	.LVL28-.Ltext0
	.long	.LVL29-.Ltext0
	.value	0x5
	.byte	0x71
	.sleb128 0
	.byte	0x35
	.byte	0x21
	.byte	0x9f
	.long	.LVL29-.Ltext0
	.long	.LVL30-.Ltext0
	.value	0x1
	.byte	0x51
	.long	0
	.long	0
.LLST21:
	.long	.LVL36-.Ltext0
	.long	.LVL37-.Ltext0
	.value	0x6
	.byte	0xc
	.long	0x3f2000
	.byte	0x9f
	.long	0
	.long	0
.LLST22:
	.long	.LVL33-.Ltext0
	.long	.LVL34-.Ltext0
	.value	0x5
	.byte	0x8
	.byte	0xfc
	.byte	0x3e
	.byte	0x24
	.byte	0x9f
	.long	0
	.long	0
.LLST23:
	.long	.LVL33-.Ltext0
	.long	.LVL34-.Ltext0
	.value	0x6
	.byte	0x9e
	.uleb128 0x4
	.long	0x803f2800
	.long	0
	.long	0
.LLST24:
	.long	.LVL34-.Ltext0
	.long	.LVL35-.Ltext0
	.value	0x6
	.byte	0xc
	.long	0x3f1000
	.byte	0x9f
	.long	0
	.long	0
.LLST25:
	.long	.LVL34-.Ltext0
	.long	.LVL35-.Ltext0
	.value	0x6
	.byte	0x9e
	.uleb128 0x4
	.long	0x803f2000
	.long	0
	.long	0
.LLST26:
	.long	.LVL35-.Ltext0
	.long	.LVL36-.Ltext0
	.value	0x6
	.byte	0xc
	.long	0x3f2000
	.byte	0x9f
	.long	0
	.long	0
.LLST27:
	.long	.LVL35-.Ltext0
	.long	.LVL36-.Ltext0
	.value	0x6
	.byte	0x9e
	.uleb128 0x4
	.long	0x803f2ffc
	.long	0
	.long	0
.LLST28:
	.long	.LVL38-.Ltext0
	.long	.LVL39-.Ltext0
	.value	0x2
	.byte	0x91
	.sleb128 4
	.long	.LVL39-.Ltext0
	.long	.LVL41-.Ltext0
	.value	0x1
	.byte	0x56
	.long	.LVL41-.Ltext0
	.long	.LVL42-.Ltext0
	.value	0x2
	.byte	0x91
	.sleb128 -36
	.long	.LVL56-.Ltext0
	.long	.LVL57-.Ltext0
	.value	0x1
	.byte	0x56
	.long	.LVL58-.Ltext0
	.long	.LVL61-.Ltext0
	.value	0x2
	.byte	0x91
	.sleb128 -36
	.long	.LVL65-.Ltext0
	.long	.LVL69-.Ltext0
	.value	0x1
	.byte	0x56
	.long	.LVL69-.Ltext0
	.long	.LVL70-.Ltext0
	.value	0x2
	.byte	0x91
	.sleb128 -36
	.long	.LVL70-.Ltext0
	.long	.LFE23-.Ltext0
	.value	0x2
	.byte	0x91
	.sleb128 4
	.long	0
	.long	0
.LLST29:
	.long	.LVL39-.Ltext0
	.long	.LVL40-.Ltext0
	.value	0xa
	.byte	0x70
	.sleb128 0
	.byte	0x46
	.byte	0x25
	.byte	0x32
	.byte	0x24
	.byte	0x72
	.sleb128 0
	.byte	0x22
	.byte	0x9f
	.long	.LVL40-.Ltext0
	.long	.LVL42-.Ltext0
	.value	0xb
	.byte	0x91
	.sleb128 0
	.byte	0x6
	.byte	0x46
	.byte	0x25
	.byte	0x32
	.byte	0x24
	.byte	0x72
	.sleb128 0
	.byte	0x22
	.byte	0x9f
	.long	.LVL56-.Ltext0
	.long	.LVL57-.Ltext0
	.value	0xb
	.byte	0x91
	.sleb128 0
	.byte	0x6
	.byte	0x46
	.byte	0x25
	.byte	0x32
	.byte	0x24
	.byte	0x72
	.sleb128 0
	.byte	0x22
	.byte	0x9f
	.long	.LVL58-.Ltext0
	.long	.LVL59-1-.Ltext0
	.value	0xb
	.byte	0x91
	.sleb128 0
	.byte	0x6
	.byte	0x46
	.byte	0x25
	.byte	0x32
	.byte	0x24
	.byte	0x72
	.sleb128 0
	.byte	0x22
	.byte	0x9f
	.long	.LVL65-.Ltext0
	.long	.LVL67-1-.Ltext0
	.value	0xb
	.byte	0x91
	.sleb128 0
	.byte	0x6
	.byte	0x46
	.byte	0x25
	.byte	0x32
	.byte	0x24
	.byte	0x72
	.sleb128 0
	.byte	0x22
	.byte	0x9f
	.long	0
	.long	0
.LLST30:
	.long	.LVL39-.Ltext0
	.long	.LVL42-.Ltext0
	.value	0x2
	.byte	0x30
	.byte	0x9f
	.long	.LVL42-.Ltext0
	.long	.LVL55-.Ltext0
	.value	0x1
	.byte	0x53
	.long	.LVL56-.Ltext0
	.long	.LVL57-.Ltext0
	.value	0x2
	.byte	0x30
	.byte	0x9f
	.long	.LVL58-.Ltext0
	.long	.LVL60-.Ltext0
	.value	0x2
	.byte	0x30
	.byte	0x9f
	.long	.LVL60-.Ltext0
	.long	.LVL62-.Ltext0
	.value	0x1
	.byte	0x50
	.long	.LVL62-.Ltext0
	.long	.LVL63-.Ltext0
	.value	0x1
	.byte	0x51
	.long	.LVL63-.Ltext0
	.long	.LVL65-.Ltext0
	.value	0x1
	.byte	0x53
	.long	.LVL65-.Ltext0
	.long	.LVL69-.Ltext0
	.value	0x2
	.byte	0x30
	.byte	0x9f
	.long	.LVL69-.Ltext0
	.long	.LVL70-1-.Ltext0
	.value	0x1
	.byte	0x50
	.long	.LVL70-1-.Ltext0
	.long	.LVL70-.Ltext0
	.value	0x1
	.byte	0x53
	.long	0
	.long	0
.LLST31:
	.long	.LVL42-.Ltext0
	.long	.LVL55-.Ltext0
	.value	0x2
	.byte	0x30
	.byte	0x9f
	.long	0
	.long	0
.LLST32:
	.long	.LVL67-.Ltext0
	.long	.LVL69-.Ltext0
	.value	0x1
	.byte	0x50
	.long	0
	.long	0
.LLST33:
	.long	.LVL65-.Ltext0
	.long	.LVL66-.Ltext0
	.value	0x3
	.byte	0x8
	.byte	0x80
	.byte	0x9f
	.long	0
	.long	0
.LLST34:
	.long	.LVL65-.Ltext0
	.long	.LVL66-.Ltext0
	.value	0xb
	.byte	0x91
	.sleb128 0
	.byte	0x6
	.byte	0x46
	.byte	0x25
	.byte	0x32
	.byte	0x24
	.byte	0x72
	.sleb128 0
	.byte	0x22
	.byte	0x9f
	.long	0
	.long	0
.LLST35:
	.long	.LVL67-.Ltext0
	.long	.LVL68-.Ltext0
	.value	0x1
	.byte	0x50
	.long	0
	.long	0
.LLST36:
	.long	.LVL42-.Ltext0
	.long	.LVL44-.Ltext0
	.value	0x2
	.byte	0x30
	.byte	0x9f
	.long	.LVL44-.Ltext0
	.long	.LVL46-.Ltext0
	.value	0x1
	.byte	0x57
	.long	.LVL46-.Ltext0
	.long	.LVL48-.Ltext0
	.value	0x3
	.byte	0x77
	.sleb128 -1
	.byte	0x9f
	.long	.LVL48-.Ltext0
	.long	.LVL55-.Ltext0
	.value	0x1
	.byte	0x57
	.long	0
	.long	0
.LLST37:
	.long	.LVL44-.Ltext0
	.long	.LVL47-.Ltext0
	.value	0x1
	.byte	0x55
	.long	.LVL47-.Ltext0
	.long	.LVL48-.Ltext0
	.value	0x4
	.byte	0x75
	.sleb128 -4096
	.byte	0x9f
	.long	.LVL48-.Ltext0
	.long	.LVL55-.Ltext0
	.value	0x1
	.byte	0x55
	.long	0
	.long	0
.LLST38:
	.long	.LVL44-.Ltext0
	.long	.LVL45-.Ltext0
	.value	0x5
	.byte	0x70
	.sleb128 0
	.byte	0x31
	.byte	0x21
	.byte	0x9f
	.long	.LVL45-.Ltext0
	.long	.LVL48-.Ltext0
	.value	0x1
	.byte	0x50
	.long	.LVL50-.Ltext0
	.long	.LVL54-.Ltext0
	.value	0x2
	.byte	0x30
	.byte	0x9f
	.long	0
	.long	0
.LLST39:
	.long	.LVL50-.Ltext0
	.long	.LVL52-.Ltext0
	.value	0x6
	.byte	0xf2
	.long	.Ldebug_info0+1997
	.sleb128 0
	.long	0
	.long	0
.LLST40:
	.long	.LVL51-.Ltext0
	.long	.LVL52-.Ltext0
	.value	0x1
	.byte	0x50
	.long	0
	.long	0
.LLST41:
	.long	.LVL64-.Ltext0
	.long	.LVL65-.Ltext0
	.value	0x1
	.byte	0x53
	.long	0
	.long	0
.LLST42:
	.long	.LVL72-.Ltext0
	.long	.LVL73-.Ltext0
	.value	0x2
	.byte	0x91
	.sleb128 0
	.long	.LVL73-.Ltext0
	.long	.LFE24-.Ltext0
	.value	0x1
	.byte	0x50
	.long	0
	.long	0
.LLST43:
	.long	.LVL72-.Ltext0
	.long	.LVL73-.Ltext0
	.value	0x2
	.byte	0x91
	.sleb128 4
	.long	.LVL73-.Ltext0
	.long	.LFE24-.Ltext0
	.value	0x1
	.byte	0x52
	.long	0
	.long	0
.LLST44:
	.long	.LVL76-.Ltext0
	.long	.LVL77-1-.Ltext0
	.value	0x1
	.byte	0x50
	.long	.LVL77-1-.Ltext0
	.long	.LVL79-.Ltext0
	.value	0x1
	.byte	0x53
	.long	.LVL79-.Ltext0
	.long	.LVL80-.Ltext0
	.value	0x1
	.byte	0x50
	.long	0
	.long	0
.LLST45:
	.long	.LVL81-.Ltext0
	.long	.LVL83-.Ltext0
	.value	0x2
	.byte	0x91
	.sleb128 0
	.long	.LVL83-.Ltext0
	.long	.LFE26-.Ltext0
	.value	0x1
	.byte	0x50
	.long	0
	.long	0
.LLST46:
	.long	.LVL81-.Ltext0
	.long	.LVL83-.Ltext0
	.value	0x2
	.byte	0x91
	.sleb128 4
	.long	.LVL83-.Ltext0
	.long	.LFE26-.Ltext0
	.value	0x1
	.byte	0x52
	.long	0
	.long	0
.LLST47:
	.long	.LVL82-.Ltext0
	.long	.LVL83-.Ltext0
	.value	0x2
	.byte	0x91
	.sleb128 4
	.long	0
	.long	0
.LLST48:
	.long	.LVL82-.Ltext0
	.long	.LVL83-.Ltext0
	.value	0x2
	.byte	0x91
	.sleb128 0
	.long	0
	.long	0
.LLST49:
	.long	.LVL84-.Ltext0
	.long	.LVL92-.Ltext0
	.value	0x1
	.byte	0x50
	.long	.LVL94-.Ltext0
	.long	.LVL95-1-.Ltext0
	.value	0x1
	.byte	0x50
	.long	0
	.long	0
.LLST50:
	.long	.LVL90-.Ltext0
	.long	.LVL94-.Ltext0
	.value	0x4
	.byte	0x71
	.sleb128 2048
	.byte	0x9f
	.long	0
	.long	0
.LLST51:
	.long	.LVL84-.Ltext0
	.long	.LVL85-.Ltext0
	.value	0x2
	.byte	0x30
	.byte	0x9f
	.long	0
	.long	0
.LLST52:
	.long	.LVL84-.Ltext0
	.long	.LVL85-.Ltext0
	.value	0x2
	.byte	0x30
	.byte	0x9f
	.long	.LVL85-.Ltext0
	.long	.LVL86-.Ltext0
	.value	0x1
	.byte	0x52
	.long	.LVL86-.Ltext0
	.long	.LVL87-.Ltext0
	.value	0x1
	.byte	0x51
	.long	.LVL87-.Ltext0
	.long	.LVL88-.Ltext0
	.value	0x1
	.byte	0x53
	.long	.LVL88-.Ltext0
	.long	.LVL89-.Ltext0
	.value	0x4
	.byte	0x72
	.sleb128 -4096
	.byte	0x9f
	.long	.LVL89-.Ltext0
	.long	.LVL91-.Ltext0
	.value	0x1
	.byte	0x52
	.long	.LVL94-.Ltext0
	.long	.LVL95-1-.Ltext0
	.value	0x1
	.byte	0x52
	.long	0
	.long	0
.LLST53:
	.long	.LVL84-.Ltext0
	.long	.LVL85-.Ltext0
	.value	0x5
	.byte	0x40
	.byte	0x4b
	.byte	0x24
	.byte	0x1f
	.byte	0x9f
	.long	.LVL85-.Ltext0
	.long	.LVL86-.Ltext0
	.value	0x7
	.byte	0x72
	.sleb128 -2147483648
	.byte	0x9f
	.long	.LVL86-.Ltext0
	.long	.LVL87-.Ltext0
	.value	0x7
	.byte	0x71
	.sleb128 -2147483648
	.byte	0x9f
	.long	.LVL87-.Ltext0
	.long	.LVL88-.Ltext0
	.value	0x7
	.byte	0x73
	.sleb128 -2147483648
	.byte	0x9f
	.long	.LVL88-.Ltext0
	.long	.LVL89-.Ltext0
	.value	0x7
	.byte	0x72
	.sleb128 2147479552
	.byte	0x9f
	.long	.LVL89-.Ltext0
	.long	.LVL91-.Ltext0
	.value	0x7
	.byte	0x72
	.sleb128 -2147483648
	.byte	0x9f
	.long	.LVL94-.Ltext0
	.long	.LVL95-1-.Ltext0
	.value	0x7
	.byte	0x72
	.sleb128 -2147483648
	.byte	0x9f
	.long	0
	.long	0
.LLST54:
	.long	.LVL85-.Ltext0
	.long	.LVL86-.Ltext0
	.value	0x5
	.byte	0x72
	.sleb128 0
	.byte	0x31
	.byte	0x21
	.byte	0x9f
	.long	.LVL86-.Ltext0
	.long	.LVL87-.Ltext0
	.value	0x5
	.byte	0x71
	.sleb128 0
	.byte	0x31
	.byte	0x21
	.byte	0x9f
	.long	.LVL87-.Ltext0
	.long	.LVL88-.Ltext0
	.value	0x5
	.byte	0x73
	.sleb128 0
	.byte	0x31
	.byte	0x21
	.byte	0x9f
	.long	.LVL88-.Ltext0
	.long	.LVL89-.Ltext0
	.value	0x1
	.byte	0x53
	.long	0
	.long	0
.LLST55:
	.long	.LVL90-.Ltext0
	.long	.LVL93-.Ltext0
	.value	0x2
	.byte	0x32
	.byte	0x9f
	.long	0
	.long	0
.LLST56:
	.long	.LVL90-.Ltext0
	.long	.LVL93-.Ltext0
	.value	0x4
	.byte	0x71
	.sleb128 2048
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
	.long	.LBB140-.Ltext0
	.long	.LBE140-.Ltext0
	.long	.LBB146-.Ltext0
	.long	.LBE146-.Ltext0
	.long	.LBB147-.Ltext0
	.long	.LBE147-.Ltext0
	.long	0
	.long	0
	.long	.LBB151-.Ltext0
	.long	.LBE151-.Ltext0
	.long	.LBB152-.Ltext0
	.long	.LBE152-.Ltext0
	.long	.LBB153-.Ltext0
	.long	.LBE153-.Ltext0
	.long	0
	.long	0
	.long	.LBB155-.Ltext0
	.long	.LBE155-.Ltext0
	.long	.LBB156-.Ltext0
	.long	.LBE156-.Ltext0
	.long	.LBB157-.Ltext0
	.long	.LBE157-.Ltext0
	.long	0
	.long	0
	.long	.LBB158-.Ltext0
	.long	.LBE158-.Ltext0
	.long	.LBB167-.Ltext0
	.long	.LBE167-.Ltext0
	.long	0
	.long	0
	.long	.LBB174-.Ltext0
	.long	.LBE174-.Ltext0
	.long	.LBB177-.Ltext0
	.long	.LBE177-.Ltext0
	.long	0
	.long	0
	.long	.LBB179-.Ltext0
	.long	.LBE179-.Ltext0
	.long	.LBB182-.Ltext0
	.long	.LBE182-.Ltext0
	.long	.LBB183-.Ltext0
	.long	.LBE183-.Ltext0
	.long	.LBB184-.Ltext0
	.long	.LBE184-.Ltext0
	.long	.LBB185-.Ltext0
	.long	.LBE185-.Ltext0
	.long	0
	.long	0
	.long	.LBB192-.Ltext0
	.long	.LBE192-.Ltext0
	.long	.LBB193-.Ltext0
	.long	.LBE193-.Ltext0
	.long	.LBB194-.Ltext0
	.long	.LBE194-.Ltext0
	.long	0
	.long	0
	.section	.debug_line,"",@progbits
.Ldebug_line0:
	.section	.debug_str,"MS",@progbits,1
.LASF50:
	.string	"_Z7kmunmapPvm"
.LASF65:
	.string	"_Z7vmallocm"
.LASF87:
	.string	"_cur_directory"
.LASF82:
	.string	"decltype(nullptr)"
.LASF76:
	.string	"_Z5panicPKc"
.LASF32:
	.string	"paddr"
.LASF24:
	.string	"pt_entry_unset_bit"
.LASF62:
	.string	"kmmap"
.LASF15:
	.string	"entries"
.LASF42:
	.string	"pd_entry_is_present"
.LASF20:
	.string	"pt_entry_set_frame"
.LASF1:
	.string	"short int"
.LASF18:
	.string	"sizetype"
.LASF81:
	.string	"/home/pfalcato/Spartix/kernel"
.LASF77:
	.string	"panic"
.LASF45:
	.string	"_Z19pt_entry_is_presentm"
.LASF17:
	.string	"pd_entry"
.LASF60:
	.string	"frame"
.LASF79:
	.string	"GNU C++11 5.3.0 -mtune=generic -march=pentiumpro -g -O2 -std=c++11 -ffreestanding -fbuiltin -fstack-protector-strong -fno-exceptions -fno-rtti"
.LASF69:
	.string	"_Z10map_kernelv"
.LASF35:
	.string	"get_directory"
.LASF85:
	.string	"alloc_page"
.LASF10:
	.string	"uintptr_t"
.LASF13:
	.string	"ptable"
.LASF84:
	.string	"_ZN3VMM4InitEv"
.LASF39:
	.string	"bool"
.LASF33:
	.string	"pd_entry_set_bit"
.LASF37:
	.string	"pd_entry_is_4MB"
.LASF3:
	.string	"long long int"
.LASF83:
	.string	"Init"
.LASF19:
	.string	"pt_entry_set_bit"
.LASF2:
	.string	"long int"
.LASF16:
	.string	"pt_entry"
.LASF48:
	.string	"addr"
.LASF30:
	.string	"pd_entry_set_frame"
.LASF36:
	.string	"_Z13get_directoryv"
.LASF72:
	.string	"pfree"
.LASF68:
	.string	"_Z5vfreePvm"
.LASF26:
	.string	"pt_entry_pfn"
.LASF74:
	.string	"loadPageDirectory"
.LASF67:
	.string	"map_kernel"
.LASF12:
	.string	"DWORD"
.LASF54:
	.string	"entry"
.LASF11:
	.string	"long double"
.LASF70:
	.string	"_Z5pfreemPv"
.LASF41:
	.string	"_Z12pd_entry_pfnm"
.LASF4:
	.string	"unsigned char"
.LASF49:
	.string	"kmunmap"
.LASF51:
	.string	"virt"
.LASF78:
	.string	"abort"
.LASF28:
	.string	"_Z12pt_entry_pfnm"
.LASF0:
	.string	"signed char"
.LASF34:
	.string	"_Z16pd_entry_set_bitPmm"
.LASF7:
	.string	"long long unsigned int"
.LASF9:
	.string	"uint32_t"
.LASF8:
	.string	"unsigned int"
.LASF66:
	.string	"vfree"
.LASF73:
	.string	"pmalloc"
.LASF64:
	.string	"_Z5kmmapmm"
.LASF58:
	.string	"entry2"
.LASF86:
	.string	"free_page"
.LASF23:
	.string	"p_addr"
.LASF43:
	.string	"_Z19pd_entry_is_presentm"
.LASF53:
	.string	"pdir"
.LASF5:
	.string	"short unsigned int"
.LASF31:
	.string	"_Z18pd_entry_set_framePmm"
.LASF27:
	.string	"switch_directory"
.LASF55:
	.string	"vaddr"
.LASF75:
	.string	"printf"
.LASF38:
	.string	"_Z15pd_entry_is_4MBm"
.LASF21:
	.string	"_Z16pt_entry_set_bitPmm"
.LASF52:
	.string	"npages"
.LASF6:
	.string	"long unsigned int"
.LASF46:
	.string	"_flush_tlb_page"
.LASF47:
	.string	"_Z15_flush_tlb_pagem"
.LASF29:
	.string	"_Z16switch_directoryPN3VMM10pdirectoryE"
.LASF63:
	.string	"vmalloc"
.LASF40:
	.string	"pd_entry_pfn"
.LASF80:
	.string	"arch/i386/vmm.cpp"
.LASF61:
	.string	"ret_addr"
.LASF57:
	.string	"table"
.LASF14:
	.string	"pdirectory"
.LASF25:
	.string	"_Z18pt_entry_unset_bitPmm"
.LASF22:
	.string	"_Z18pt_entry_set_framePmm"
.LASF59:
	.string	"entry3"
.LASF56:
	.string	"page"
.LASF71:
	.string	"_Z7pmallocm"
.LASF44:
	.string	"pt_entry_is_present"
	.ident	"GCC: (GNU) 5.3.0"
