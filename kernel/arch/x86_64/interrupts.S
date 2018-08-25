/*
 Copyright (c) 2016, 2017, 2018 Pedro Falcato
 This file is part of Onyx, and is released under the terms of the MIT License
 check LICENSE at the root directory for more information
*/

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

.macro ISR_NOERRCODE num
.global isr\num
isr\num:
	cli
	push $0 # Push a dummy error code to align the stack
	push $\num # Push the interrupt number
	pushaq
	jmp isr_common # Go to the handler
.endm


#define IRQ_STACK_OFF_CS		136
#define KERNEL_CS			0x08
.global irq_common
irq_common:
	cld
	mov %ds, %ax
	push %rax
	mov $0x10, %ax
	mov %ax, %ss
	mov %ax, %ds
	mov %ax, %es

	mov IRQ_STACK_OFF_CS(%rsp), %rax
	cmp $KERNEL_CS, %rax
	je .L3
	swapgs
.L3:
	push %rdi
	call platform_send_eoi
	pop %rdi
	mov %rsp, %rsi
	# End the stack frame list so we stop here
	xor %rbp, %rbp
	call irq_handler
	mov %rax, %rsp
	call signal_is_pending
	cmp $1, %rax
	je .L4
.L5:
	mov IRQ_STACK_OFF_CS(%rsp), %rax
	cmp $KERNEL_CS, %rax
	je .L6
	swapgs
.L6:
	pop %rax
	mov %ax, %ds
	mov %ax, %es

	popaq
	iretq

.L4:
	mov %rsp, %rdi
	mov $0, %rsi
	call handle_signal
	jmp .L5

.macro IRQ irq_num
.global irq\irq_num
irq\irq_num:
	cli
	pushaq
	mov $\irq_num, %rdi
	jmp irq_common

.global irq\irq_num\()_end
irq\irq_num\()_end:

.endm


.macro ISR_ERRCODE num
.global isr\num
isr\num:
	cli
	push $\num # Push the interrupt number to the intctx
	pushaq
	jmp isr_common # Go to the handler
.endm

#define ISR_STACK_FRAME_CS_OFF		152

.global isr_common
isr_common:
	cld
	xor %rbp, %rbp

	mov %ds, %rax
	push %rax
	mov $0x10, %ax
	mov %ax, %ss
	mov %ax, %ds
	mov %ax, %es

	mov ISR_STACK_FRAME_CS_OFF(%rsp), %rax
	cmp $KERNEL_CS, %rax
	je .L0
	swapgs
.L0:
	mov %rsp, %rdi
	call isr_handler

	call signal_is_pending
	cmp $1, %rax
	je .Lisr_handle_signal
.L1:
	mov ISR_STACK_FRAME_CS_OFF(%rsp), %rax
	cmp $KERNEL_CS, %rax
	je .L2
	swapgs
.L2:
	pop %rax
	mov %ax, %ds
	mov %ax, %es

	popaq
	add $16, %rsp
	iretq

.Lisr_handle_signal:
	mov %rsp, %rdi
	mov $1, %rsi
	call handle_signal
	jmp .L1

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

.global _sched_yield
_sched_yield:
	cli
	pushaq
	mov %ds, %ax
	push %rax
	mov $0x10, %ax
	mov %ax, %ds
	mov %ax, %es

	mov %rsp, %rdi
	mov IRQ_STACK_OFF_CS(%rsp), %rax
	cmp $KERNEL_CS, %rax
	je .L7
	swapgs
.L7:
	call sched_switch_thread
	mov %rax, %rsp
	mov IRQ_STACK_OFF_CS(%rsp), %rax
	cmp $KERNEL_CS, %rax
	je .L8
	swapgs
.L8:
	pop %rax
	mov %ax, %ds
	mov %ax, %es

	popaq
	iretq

.global __sigret_return
__sigret_return:
	cli
	mov %rdi, %rsp
	swapgs
	pop %rcx
	mov %cx, %ds
	mov %cx, %es
	popaq
	iretq

.global apic_spurious_irq
apic_spurious_irq:
	iretq

.global __cpu_handle_message
__cpu_handle_message:
	cli
	pushaq
	mov %ds, %ax
	push %rax
	mov $0x10, %ax
	mov %ax, %ss
	mov %ax, %ds
	mov %ax, %es

	mov IRQ_STACK_OFF_CS(%rsp), %rax
	cmp $KERNEL_CS, %rax
	je .L9
	swapgs
.L9:
	# End the stack frame list so we stop here
	xor %rbp, %rbp
	mov %rsp, %rdi
	call cpu_handle_messages

	mov %rax, %rsp
	call lapic_send_eoi

	mov IRQ_STACK_OFF_CS(%rsp), %rax
	cmp $KERNEL_CS, %rax
	je .L10
	swapgs
.L10:
	pop %rax
	mov %ax, %ds
	mov %ax, %es

	popaq
	iretq