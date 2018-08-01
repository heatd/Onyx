section .text

global __copy_non_temporal
; __copy_non_temporal assumes that the buffers are properly aligned for the copy
; Failure to do so will result in worse performance
; __copy_non_temporal also assumes that the byte count is also aligned

; RDI holds destination buffer
; RSI holds source buffer
; RDX holds byte count
__copy_non_temporal:

prefetchnta [rsi]

.loop:
	mov rax, [rsi]
	movnti [rdi], rax
	add rdi, 8
	add rsi, 8
	sub rdx, 8

	jnz .loop

xor rax, rax

ret

global __set_non_temporal
; __set_non_temporal assumes that the buffer is properly aligned for the memset
; Failure to do so will result in worse performance
; __set_non_temporal also assumes that the byte count is also aligned

; RDI holds destination buffer
; RSI holds byte value
; RDX holds byte count
__set_non_temporal:

; Since the byte value is probably not set up like we want it to,
; fill the register using the byte, so we can copy 8 bytes at a time

; Byte 0
mov r8, rsi
and r8, 0xff
mov rax, r8
; Byte 1
shl r8, 8
or rax, r8
; Byte 2
shl r8, 8
or rax, r8
; Byte 3
shl r8, 8
or rax, r8
; Byte 4
shl r8, 8
or rax, r8
; Byte 5
shl r8, 8
or rax, r8
; Byte 6
shl r8, 8
or rax, r8
; Byte 7
shl r8, 8
or rax, r8

.loop:
	movnti [rdi], rax
	add rdi, 8
	sub rdx, 8

	jnz .loop

xor rax, rax

ret