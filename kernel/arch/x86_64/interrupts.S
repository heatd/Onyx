section .text
%macro ISR_NOERRCODE 1
global isr%1
isr%1:
	cli
	xor rdx,rdx   ;push dummy err code
	mov rsi, %1  ;push the interrupt number
	jmp isr_common ;Go to the handler
%endmacro
%macro IRQ 2
global irq%1
irq%1:
cli
mov rdx, 
jmp irq_common
%endmacro
%macro ISR_ERRCODE 1
global isr%1
isr%1:
	cli
	pop rdx
	mov rsi, %1 ;push the interrupt number
	jmp isr_common ;Go to the handler
%endmacro

extern isr_handler
global isr_common
isr_common:
	mov ax,ds
	xor rdi,rdi
	mov di,ax
	mov ax,10h
	mov ds,ax
	mov ss,ax
	mov es,ax
	mov fs,ax
	mov gs,ax
	call isr_handler
	mov ax,si
	mov ds,ax
	mov ss,ax
	mov es,ax
	mov fs,ax
	mov fs,ax
	iretq

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
