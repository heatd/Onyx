section .text
global read_ip
read_ip:
	pop eax
	jmp eax
global preempt
extern loadPageDirectory
preempt:
	;load all the registers
	mov eax,[esp + 4]
	mov ecx,[eax + 8]
	mov edx,[eax + 12]
	mov esi,[eax + 16]
	mov edi,[eax + 20]
	mov ebp,[eax + 28]
	pushf
	sub esp,4
	mov ebx,[eax + 4]
	push ebx
	popf
	mov esp,[eax + 24]
	mov ebx,[eax + 40]
	push ebx
	call loadPageDirectory
	mov ebx,[eax + 32]
	mov eax,[eax]
	jmp ebx;jump to the eip