section .data
	msg db 'Test'
section .text
test:
	push msg
	extern printf
	call printf
	cli
	hlt
global switch_task
switch_task:
	mov esp, 0x80600000
	pop eax
	push dword test
	ret