/*
 Copyright (c) 2016, 2017, 2018 Pedro Falcato
 This file is part of Onyx, and is released under the terms of the MIT License
 check LICENSE at the root directory for more information
*/

#include <onyx/registers.h>
#include <onyx/x86/segments.h>

.section .text

.macro pushaq
	push %rax
	push %rbx
	push %rcx
	push %rdx
	push %rdi
	push %rsi
	push %rbp
	push %r8
	push %r9
	push %r10
	push %r11
	push %r12
	push %r13
	push %r14
	push %r15
.endm

.macro popaq
	pop %r15
	pop %r14
	pop %r13
	pop %r12
	pop %r11
	pop %r10
	pop %r9
	pop %r8
	pop %rbp
	pop %rsi
	pop %rdi
	pop %rdx
	pop %rcx
	pop %rbx
	pop %rax
.endm

.macro CFI_INTERRUPT_FRAME_BEFORE_DS
	.cfi_def_cfa rsp, 0
	.cfi_offset rip, REGISTER_OFF_RIP-8
	.cfi_offset cs, REGISTER_OFF_CS-8
	.cfi_offset rsp, REGISTER_OFF_RSP-8
	.cfi_offset ss, REGISTER_OFF_SS-8
	.cfi_offset r15, REGISTER_OFF_R15-8
	.cfi_offset r14, REGISTER_OFF_R14-8
	.cfi_offset r13, REGISTER_OFF_R13-8
	.cfi_offset r12, REGISTER_OFF_R12-8
	.cfi_offset r11, REGISTER_OFF_R11-8
	.cfi_offset r10, REGISTER_OFF_R10-8
	.cfi_offset r9, REGISTER_OFF_R9-8
	.cfi_offset r8, REGISTER_OFF_R8-8
	.cfi_offset rbp, REGISTER_OFF_RBP-8
	.cfi_offset rsi, REGISTER_OFF_RSI-8
	.cfi_offset rdi, REGISTER_OFF_RDI-8
	.cfi_offset rdx, REGISTER_OFF_RDX-8
	.cfi_offset rcx, REGISTER_OFF_RCX-8
	.cfi_offset rbx, REGISTER_OFF_RBX-8
	.cfi_offset rax, REGISTER_OFF_RAX-8
.endm

.macro CFI_INTERRUPT_FRAME reg
	.cfi_def_cfa reg, 0
	.cfi_offset ds, 0
	.cfi_offset rip, REGISTER_OFF_RIP
	.cfi_offset cs, REGISTER_OFF_CS
	.cfi_offset rsp, REGISTER_OFF_RSP
	.cfi_offset ss, REGISTER_OFF_SS
	.cfi_offset r15, REGISTER_OFF_R15
	.cfi_offset r14, REGISTER_OFF_R14
	.cfi_offset r13, REGISTER_OFF_R13
	.cfi_offset r12, REGISTER_OFF_R12
	.cfi_offset r11, REGISTER_OFF_R11
	.cfi_offset r10, REGISTER_OFF_R10
	.cfi_offset r9, REGISTER_OFF_R9
	.cfi_offset r8, REGISTER_OFF_R8
	.cfi_offset rbp, REGISTER_OFF_RBP
	.cfi_offset rsi, REGISTER_OFF_RSI
	.cfi_offset rdi, REGISTER_OFF_RDI
	.cfi_offset rdx, REGISTER_OFF_RDX
	.cfi_offset rcx, REGISTER_OFF_RCX
	.cfi_offset rbx, REGISTER_OFF_RBX
	.cfi_offset rax, REGISTER_OFF_RAX
.endm

/* Should be used after pushing %ds */
.macro CFI_INTERRUPT_FRAME_ADJUST_DS
	.cfi_adjust_cfa_offset 8
	.cfi_offset ds, 0
.endm

.macro INTERRUPT_STACK_ALIGN
	/* After pushing the interrupt frame we're left with an 8-byte aligned stack,
	 * so align it by subbing 8 bytes
	*/
	sub $8, %rsp
.endm

.macro INTERRUPT_STACK_RESTORE
	add $8, %rsp
.endm

/* struct registers has two longs that are used only for ISRs,
 and meaningless otherwise
*/
#define REGISTERS_UNUSED_OFF		16

#define EXCEPTION_VECTORS_END       32

.macro ISR_NOERRCODE num
.global isr\num
isr\num:
	cli
	sub $8, %rsp
	push $\num # Push the interrupt number
	jmp x86_interrupt_common # Go to the handler

.pushsection .rodata.isr_table
.quad isr\num
.popsection

.endm

.macro IRQ irq_num
.global irq\irq_num
irq\irq_num:
	cli
	sub $8, %rsp
	push $(\irq_num + EXCEPTION_VECTORS_END)
	jmp x86_interrupt_common

.pushsection .rodata.isr_table
.quad irq\irq_num
.popsection

.endm

.macro ISR_ERRCODE num
.global isr\num
isr\num:
	cli
	push $\num # Push the interrupt number to the intctx
	jmp x86_interrupt_common # Go to the handler

.pushsection .rodata.isr_table
.quad isr\num
.popsection

.endm

.global x86_interrupt_ret
.type x86_interrupt_ret, @function
x86_interrupt_ret:
	call signal_is_pending
	cmp $1, %al
	je 1f

2:
	INTERRUPT_STACK_RESTORE
.global x86_scheduler_exit
x86_scheduler_exit:
	/* We'll use this bit of code as a trampoline to the new thread too */
	mov REGISTER_OFF_CS(%rsp), %rax
	test $3, %rax
	cli
	jz 3f
	swapgs
3:
	pop %rax
	mov %ax, %ds
	mov %ax, %es

	popaq

	add $REGISTERS_UNUSED_OFF, %rsp
	iretq
1:
	mov %rsp, %rdi
	add $8, %rdi
	call handle_signal
	jmp 2b

x86_interrupt_common:
	.cfi_startproc
	pushaq
	CFI_INTERRUPT_FRAME_BEFORE_DS
	cld

	mov %ds, %ax
	push %rax
	CFI_INTERRUPT_FRAME_ADJUST_DS
	mov $KERNEL_DS, %ax
	mov %ax, %ss
	mov %ax, %ds
	mov %ax, %es

	mov REGISTER_OFF_CS(%rsp), %rax
	test $3, %rax

	jz .L3
	swapgs
.L3:
	mov %rsp, %rdi
	mov %rdi, %rbp

	.cfi_def_cfa_register rbp
	# End the stack frame list so we stop here
	#xor %rbp, %rbp

	INTERRUPT_STACK_ALIGN

	call x86_dispatch_interrupt

	mov %rax, %rsp

	jmp x86_interrupt_ret

.cfi_endproc

.pushsection .rodata.isr_table
.balign 8
.global x86_isr_table
.type x86_isr_table, STT_OBJECT
x86_isr_table:
.popsection

ISR_NOERRCODE 0
ISR_NOERRCODE 1
ISR_NOERRCODE 2
ISR_NOERRCODE 3
ISR_NOERRCODE 4
ISR_NOERRCODE 5
ISR_NOERRCODE 6
ISR_NOERRCODE 7
ISR_ERRCODE   8
ISR_NOERRCODE 9
ISR_ERRCODE   10
ISR_ERRCODE   11
ISR_ERRCODE   12
ISR_ERRCODE   13
ISR_ERRCODE   14
ISR_NOERRCODE 15
ISR_NOERRCODE 16
ISR_NOERRCODE 17
ISR_NOERRCODE 18
ISR_NOERRCODE 19
ISR_NOERRCODE 20
ISR_NOERRCODE 21
ISR_NOERRCODE 22
ISR_NOERRCODE 23
ISR_NOERRCODE 24
ISR_NOERRCODE 25
ISR_NOERRCODE 26
ISR_NOERRCODE 27
ISR_NOERRCODE 28
ISR_NOERRCODE 29
ISR_NOERRCODE 30
ISR_NOERRCODE 31
IRQ 0
IRQ 1
IRQ 2
IRQ 3
IRQ 4
IRQ 5
IRQ 6
IRQ 7
IRQ 8
IRQ 9
IRQ 10
IRQ 11
IRQ 12
IRQ 13
IRQ 14
IRQ 15
IRQ 16
IRQ 17
IRQ 18
IRQ 19
IRQ 20
IRQ 21
IRQ 22
IRQ 23
IRQ 24
IRQ 25
IRQ 26
IRQ 27
IRQ 28
IRQ 29
IRQ 30
IRQ 31
IRQ 32
IRQ 33
IRQ 34
IRQ 35
IRQ 36
IRQ 37
IRQ 38
IRQ 39
IRQ 40
IRQ 41
IRQ 42
IRQ 43
IRQ 44
IRQ 45
IRQ 46
IRQ 47
IRQ 48
IRQ 49
IRQ 50
IRQ 51
IRQ 52
IRQ 53
IRQ 54
IRQ 55
IRQ 56
IRQ 57
IRQ 58
IRQ 59
IRQ 60
IRQ 61
IRQ 62
IRQ 63
IRQ 64
IRQ 65
IRQ 66
IRQ 67
IRQ 68
IRQ 69
IRQ 70
IRQ 71
IRQ 72
IRQ 73
IRQ 74
IRQ 75
IRQ 76
IRQ 77
IRQ 78
IRQ 79
IRQ 80
IRQ 81
IRQ 82
IRQ 83
IRQ 84
IRQ 85
IRQ 86
IRQ 87
IRQ 88
IRQ 89
IRQ 90
IRQ 91
IRQ 92
IRQ 93
IRQ 94
IRQ 95
IRQ 96
IRQ 97
IRQ 98
IRQ 99
IRQ 100
IRQ 101
IRQ 102
IRQ 103
IRQ 104
IRQ 105
IRQ 106
IRQ 107
IRQ 108
IRQ 109
IRQ 110
IRQ 111
IRQ 112
IRQ 113
IRQ 114
IRQ 115
IRQ 116
IRQ 117
IRQ 118
IRQ 119
IRQ 120
IRQ 121
IRQ 122
IRQ 123
IRQ 124
IRQ 125
IRQ 126
IRQ 127
IRQ 128
IRQ 129
IRQ 130
IRQ 131
IRQ 132
IRQ 133
IRQ 134
IRQ 135
IRQ 136
IRQ 137
IRQ 138
IRQ 139
IRQ 140
IRQ 141
IRQ 142
IRQ 143
IRQ 144
IRQ 145
IRQ 146
IRQ 147
IRQ 148
IRQ 149
IRQ 150
IRQ 151
IRQ 152
IRQ 153
IRQ 154
IRQ 155
IRQ 156
IRQ 157
IRQ 158
IRQ 159
IRQ 160
IRQ 161
IRQ 162
IRQ 163
IRQ 164
IRQ 165
IRQ 166
IRQ 167
IRQ 168
IRQ 169
IRQ 170
IRQ 171
IRQ 172
IRQ 173
IRQ 174
IRQ 175
IRQ 176
IRQ 177
IRQ 178
IRQ 179
IRQ 180
IRQ 181
IRQ 182
IRQ 183
IRQ 184
IRQ 185
IRQ 186
IRQ 187
IRQ 188
IRQ 189
IRQ 190
IRQ 191
IRQ 192
IRQ 193
IRQ 194
IRQ 195
IRQ 196
IRQ 197
IRQ 198
IRQ 199
IRQ 200
IRQ 201
IRQ 202
IRQ 203
IRQ 204
IRQ 205
IRQ 206
IRQ 207
IRQ 208
IRQ 209
IRQ 210
IRQ 211
IRQ 212
IRQ 213
IRQ 214
IRQ 215
IRQ 216
IRQ 217
IRQ 218
IRQ 219
IRQ 220
IRQ 221
IRQ 222
IRQ 223
IRQ 224
IRQ 225


.pushsection .rodata.isr_table
.global x86_isr_table_end
x86_isr_table_end:
.popsection

.global platform_yield
platform_yield:
	.cfi_startproc
	/* Basically we need to set up an IRQ frame on the stack.
	 * For future reference consult include/(carbon/onyx)/x86/registers.h
	*/
	/* Set up a regular stack frame first */
	push %rbp
	mov %rsp, %rbp
	push %rax	/* We're going to need rax as a scratch register */
	push $KERNEL_DS /* %ss */
	mov %rsp, %rax
	add $8, %rax
	push %rax /* %rsp */
	pushf /* %rflags */
	cli
	push $KERNEL_CS /* %cs */
	push $.return_label /* %rip */
	sub $REGISTERS_UNUSED_OFF, %rsp
	pushaq /* General purpose registers (%rax - %r15) */
	push $KERNEL_DS /* %ds */
	mov %rsp, %rdi
	call sched_schedule
	mov %rax, %rsp
	jmp x86_scheduler_exit
.return_label:
	pop %rax
	pop %rbp

	ret
	.cfi_endproc
	

.global __sigret_return
__sigret_return:
	cli

	mov %rdi, %rsp
	
	swapgs

	pop %rcx
	mov %cx, %ds
	mov %cx, %es
	popaq

	add $REGISTERS_UNUSED_OFF, %rsp
	iretq

.global apic_spurious_irq
apic_spurious_irq:
	iretq
