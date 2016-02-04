section .data
	msg db 'SYSCALL WORKS',0
section .text
test:
	xor eax,eax
	mov ebx, msg
	int 0x80
	jmp .lp
.lp:
	jmp .lp
global jump_userspace
jump_userspace:
	mov ax,0x23
	mov ds,ax
	mov es,ax
	mov fs,ax
	mov gs,ax
	
	mov eax,esp
	push 0x23
	push eax
	pushf 
	push 0x1B
	push test
	iret
	
