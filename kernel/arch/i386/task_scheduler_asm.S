section .text
global switch_task
switch_task:
	cli
	push eax ;Save the old eax value
	mov eax,[esp + 8] ;Get the register struct where we will save our old regs
	mov [eax + 4],ebx
	mov [eax + 8],ecx
	mov [eax + 12],edx
	mov [eax + 16],esi
	mov [eax + 20],edi
	mov [eax + 24],esp
	mov [eax + 28],ebp
	mov ebx,[esp + 4]
	mov [eax + 32],ebx
	pushf
	pop ebx
	mov [eax + 36],ebx ;Save eflags
	mov ebx,cr3
	mov [eax + 40],ebx ;Save cr3
	pop ebx
	mov [eax],ebx ; Save eax
	mov eax,[esp + 12]
	mov ecx,[eax + 8]
	mov edx,[eax + 12]
	mov esi,[eax + 16]
	mov edi,[eax + 20]
	mov esp,[eax + 24]
	mov ebp,[eax + 40] ;Lets load cr3 into ebp
	mov cr3,ebp ; And load it into cr3
	mov ebp,[eax + 36]
	push ebp
	popf
	mov ebp,[eax + 28]
	mov ebx,[eax + 32]
	push ebx
	mov ebx,[eax + 4]
	sti
	ret