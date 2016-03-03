; Copyright 2016 Pedro Falcato
;
;Licensed under the Apache License, Version 2.0 (the "License");
;you may not use this file except in compliance with the License.
;You may obtain a copy of the License at
;
;http ://www.apache.org/licenses/LICENSE-2.0
;
;Unless required by applicable law or agreed to in writing, software
;distributed under the License is distributed on an "AS IS" BASIS,
;WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
;See the License for the specific language governing permissions and
;limitations under the License.
section .text

%macro IRQ 2
global irq%1
irq%1:
cli
push byte %2
jmp irq_common
%endmacro

%macro ISR_NOERRCODE 1
global isr%1
isr%1:
	cli
	push byte 0   ;push dummy err code
	push byte %1  ;push the interrupt number
	jmp isr_common ;Go to the handler
%endmacro


%macro ISR_ERRCODE 1
global isr%1
isr%1:
	cli
	push byte %1 ;push the interrupt number
	jmp isr_common ;Go to the handler
%endmacro
global _yield
_yield:
	pusha
	push ds
	push es
	push fs
	push gs
	mov eax,10h
	mov ds,eax
	mov es,eax
	mov fs,eax
	mov gs,eax
	push esp
	extern SwitchTask
	call SwitchTask
	mov esp,eax
	mov al,20h
	out 20h,al
	pop gs
	pop fs
	pop es
	pop ds
	popa
	iret
extern isr_handler
global isr_common
isr_common:
	mov ax,ds
	push eax
	mov ax,10h
	mov ds,ax
	mov ss,ax
	mov es,ax
	mov fs,ax
	mov gs,ax
	call isr_handler
	pop eax
	mov ds,ax
	mov ss,ax
	mov es,ax
	mov fs,ax
	mov fs,ax
	add esp, 8
	iret
extern irq_handler
global irq_common:
irq_common:
	call irq_handler
	pop byte eax
	iret
extern syscall
global _syscall
_syscall:
	call syscall
	iret
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
global irq0
irq0:
	pusha
	push ds
	push es
	push fs
	push gs
	mov eax,10h
	mov ds,eax
	mov es,eax
	mov fs,eax
	mov gs,eax
	push esp
	extern SwitchTask
	extern timer_handler
	call SwitchTask
	call timer_handler
	mov esp,eax
	mov al,20h
	out 20h,al
	pop gs
	pop fs
	pop es
	pop ds
	popa
	iret
IRQ 1,33
IRQ 2,34
IRQ 3,35
IRQ 4,36
IRQ 5,37
IRQ 6,38
IRQ 7 ,39
IRQ 8 ,40
IRQ 9 ,41
IRQ 10 ,42
IRQ 11 ,43
IRQ 12 ,44
IRQ 13 ,45
IRQ 14 ,46
IRQ 15 ,47
