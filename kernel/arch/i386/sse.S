section .data
	ErrorMSG db 'Spartix needs SSE to be supported!', 0
section .text
global init_sse
init_sse:
	mov eax, 0x1
	cpuid
	test edx, 1<<25
	jz .noSSE
	mov eax, cr0
	and ax, 0xFFFB
	or ax, 0x2
	mov cr0, eax
	mov eax, cr4
	or ax, 3 << 9
	mov cr4, eax
	ret
.noSSE:
	push ErrorMSG
	extern printf
	call printf 
