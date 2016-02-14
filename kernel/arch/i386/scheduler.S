section .text
global switch_task
switch_task:
	cli ;Disable interrupts,so we don't get interrupted in the process
	push eax ;Save the original value of eax
	;I have no clue why,but gcc is pushing one more value to the stack
	mov eax,[esp + 12]
	mov [eax + 4],ebx
	mov [eax + 8],ecx
	mov [eax + 12],edx
	mov [eax + 16],edi
	mov [eax + 20],esi
	mov [eax + 24],esp
	mov [eax + 28],ebp
	mov ebx,[esp + 8]
	mov [eax + 32],ebx ;Save eip
	pop ebx
	mov [eax],ebx
	pushf
	pop ebx
	mov [eax + 36],ebx;Save eflags
	mov ebx,cr3
	mov [eax + 40],ebx;Save cr3
	;All registers saved,start loading the new ones
	mov eax,[esp + 12]
	mov ebx,[eax + 4]
	mov ecx,[eax + 8]
	mov edx,[eax + 12]
	mov edi,[eax + 16]
	mov esi,[eax + 20]
	mov esp,[eax + 24]
	mov ebp,[eax + 40]
	;mov cr3,ebp ;Load the new Page Directory
	mov ebp,[eax + 36] ;EFLAGS
	push ebp
	popf
	mov ebp,[eax + 32]
	push ebp
	mov ebp,[eax + 28]
	mov eax,[eax]
	sti
	ret