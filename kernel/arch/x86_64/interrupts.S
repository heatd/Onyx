;
; Copyright (c) 2016, 2017 Pedro Falcato
; This file is part of Onyx, and is released under the terms of the MIT License
; check LICENSE at the root directory for more information
;
section .text
%macro pushaq 0
	push rax
	push rbx
	push rcx
	push rdx
	push rdi
	push rsi
	push rbp
	push r8
	push r9
	push r10
	push r11
	push r12
	push r13
	push r14
	push r15
%endmacro
%macro popaq 0
	pop r15
	pop r14
	pop r13
	pop r12
	pop r11
	pop r10
	pop r9
	pop r8
	pop rbp
	pop rsi
	pop rdi
	pop rdx
	pop rcx
	pop rbx
	pop rax
%endmacro
%macro ISR_NOERRCODE 1
global isr%1
isr%1:
	cli
	push 0 ;push dummy err code
	push %1 ;push the interrupt number
	pushaq
	jmp isr_common ;Go to the handler
%endmacro
extern irq_handler
extern handle_signal
extern signal_is_pending
extern platform_send_eoi
global irq_common:function
irq_common:
	cld
	mov ax, ds
	push rax
	mov ax, 0x10
	mov ss, ax
	mov ds, ax
	mov es, ax
	mov rax, [rsp + 136]
	cmp rax, 0x8
	je .skip_swapgs
	swapgs
.skip_swapgs:
	push rdi
	call platform_send_eoi
	pop rdi
	mov rsi, rsp
	; End the stack frame list so we stop here
	xor rbp, rbp
	call irq_handler
	mov rsp, rax
	call signal_is_pending
	cmp rax, 1
	je .handle_signal
.continue:
	mov rax, [rsp + 136]
	cmp rax, 0x8
	je .skip_swapgs2
	swapgs
.skip_swapgs2:
	pop rax
	mov ds, ax
	mov es, ax
	popaq
	iretq
.handle_signal:
	mov rdi, rsp
	mov rsi, 0
	call handle_signal
	jmp .continue
%macro IRQ 1
global irq%1
irq%1:
cli
pushaq
mov rdi, %1
jmp irq_common
global irq%1_end
irq%1_end:
%endmacro


%macro ISR_ERRCODE 1
global isr%1
isr%1:
	cli
	push %1 ;push the interrupt number to the intctx
	pushaq
	jmp isr_common ;Go to the handler
%endmacro

extern isr_handler
global isr_common:function
isr_common:
	cld
	xor rbp, rbp
	mov rax, ds
	push rax
	mov ax, 0x10
	mov ds, ax
	mov es, ax
	mov ss, ax
	mov rax, [rsp + 152]
	cmp rax, 0x8
	je .skip_swap
	swapgs
.skip_swap: 
	mov rdi, rsp
	call isr_handler
	call signal_is_pending
	cmp rax, 1
	je .isr_handle_signal
.isr_continue:
	mov rax, [rsp + 152]
	cmp rax, 0x8
	je .skip_swap2
	swapgs
.skip_swap2:
	pop rax
	mov ds, ax
	mov es, ax
	popaq
	add rsp, 16
	iretq
.isr_handle_signal:
	mov rdi, rsp
	mov rsi, 1
	call handle_signal
	jmp .isr_continue
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

global _sched_yield:function
extern sched_switch_thread
_sched_yield:
	cli
	pushaq
	mov ax, ds
	push rax
	mov rdi, rsp
	mov rax, [rsp + 136]
	cmp rax, 0x8
	je .skip_swap_yield
	swapgs
.skip_swap_yield:
	call sched_switch_thread
	mov rsp, rax
	mov rax, [rsp + 136]
	cmp rax, 0x8
	je .skip_swap_yield2
	swapgs
.skip_swap_yield2:
	pop rax
	mov ds, ax
	mov es, ax
	popaq
	iretq
%macro syscallsaveregs 0
	push rbx
	push rcx
	push rdx
	push rdi
	push rsi
	push rbp
	push r8
	push r9
	push r10
	push r12
	push r13
	push r14
	push r15
%endmacro
%macro syscallpopregs 0
	pop r15
	pop r14
	pop r13
	pop r12
	pop r10
	pop r9
	pop r8
	pop rbp
	pop rsi
	pop rdi
	pop rdx
	pop rcx
	pop rbx
%endmacro

global __sigret_return
__sigret_return:
	cli
	mov rsp, rdi
	swapgs
	pop rcx
	mov ds, cx
	mov es, cx
	popaq
	iretq
global apic_spurious_irq:function
apic_spurious_irq:
	iretq

extern lapic_send_eoi
extern cpu_handle_messages
global __cpu_handle_message:function
__cpu_handle_message:
	cli
	pushaq
	mov ax, ds
	push rax
	mov ax, 0x10
	mov ss, ax
	mov ds, ax
	mov es, ax
	mov rax, [rsp + 136]
	cmp rax, 0x8
	je .skip_swapgs
	swapgs
.skip_swapgs:
	; End the stack frame list so we stop here
	xor rbp, rbp
	mov rdi, rsp
	call cpu_handle_messages
	mov rsp, rax
	call lapic_send_eoi
.continue:
	mov rax, [rsp + 136]
	cmp rax, 0x8
	je .skip_swapgs2
	swapgs
.skip_swapgs2:
	pop rax
	mov ds, ax
	mov es, ax
	popaq
	iretq