;----------------------------------------------------------------------
; * Copyright (C) 2016 Pedro Falcato
; *
; * This file is part of Spartix, and is made available under
; * the terms of the GNU General Public License version 2.
; *
; * You can redistribute it and/or modify it under the terms of the GNU
; * General Public License version 2 as published by the Free Software
; * Foundation.
; *----------------------------------------------------------------------
bits 32
section .multiboot
align 4
hdr_start:
	dd 0xe85250d6
	dd 0
	dd hdr_end - hdr_start
	dd 0x100000000 - (0xe85250d6 + 0 + (hdr_end - hdr_start))
	align 8 ;All tags need to be 8 byte aligned
	;Framebuffer tag
	dw 5
	dw 0
	dd 20
	dd 1024
	dd 768
	dd 32
	align 8
	; Module alignment tag
	dw 6
	dw 0
	dd 8
	align 8
	;Finish tag
	dw 0
	dw 0
	dd 8
hdr_end:
[SECTION .boot]
[GLOBAL EntryPoint]
EntryPoint:
	cli
	push eax
	push ebx
	mov eax, gdtr1
	lgdt [eax]

	push 0x08
	push .gdtrdy
	retf

.gdtrdy:
	mov eax, 0x10
	mov ds, ax
	mov ss, ax

	call setup_paging_and_longm

	mov eax, gdtr2
	lgdt [gdtr2]

	push 0x08
	push .gdt2rdy
	retf

[BITS 64]
.gdt2rdy:
	mov eax, 0x10
	mov ds, ax
	mov es, ax
	mov ss, ax

	; If you later decide to unmap the lower zone, you will have an invalid GDT if you're still using gdtr2
	mov rax, gdtr3
	lgdt [rax]
	pop rbx
	xor rsi,rsi
	mov rsi, rbx
	shr rsi, 32

	mov r8,rbx
	xor rdi,rdi
	mov edi,r8d
	mov rax, _start
	jmp rax
section .bootstrap_stack, nobits
align 4
stack_bottom:
	resb 16384
stack_top:

section .text
test:
jmp test
global user_space
user_space:
	mov ax,0x23
	mov ds,ax
	mov es,ax
	mov fs,ax
	mov gs,ax ;we don't need to worry about SS. it's handled by iret
	mov rcx, test
	pushf
	pop r11
	o64 sysret
extern kernel_early
extern kernel_main
extern _init
_start:
	mov rsp, stack_top
	call initsse
	extern __syscall
	call __syscall
	call kernel_early
	call _init
	call kernel_main
	cli
.Lhang:
	hlt
	jmp .Lhang

section .data
	error_msg db 'Spartix needs SSE to be supported!', 0
section .text
global initsse
initsse:
	mov rax, 0x1
	cpuid
	test edx, 1<<25
	jz .noSSE
	mov rax, cr0
	and ax, 0xFFFB
	or ax, 0x2
	mov cr0, rax
	mov rax, cr4
	or ax, 3 << 9
	mov cr4, rax
	ret
.noSSE:
	hlt
section .boot
[BITS 32]
extern pml4
extern pdpt
extern pd
extern pdlower
setup_paging_and_longm:
	mov eax, pdpt
	or eax, 3
	or eax, 1 << 2
	mov [pml4], eax
	mov [pml4 + 0xFF8], eax
	mov eax, pdlower
	or eax, 3
	or eax, 1 << 8
	or eax, 1 << 2
	mov [pdpt], eax
	mov eax, pd
	or eax, 3
	or eax, 1 << 8
	or eax, 1 << 2
	mov [pdpt + 0xFF0], eax

	mov dword [pd], 0x000083
	or dword [pd], 1 << 8
	mov dword [pd + 8], 0x200083
	or dword [pd + 8], 1 << 8

	mov dword [pdlower], 0x000083
	or dword [pdlower], 1 << 8
	mov dword [pdlower + 8], 0x200083
	or dword [pdlower + 8], 1 << 8
	; Load CR3 with PML4
	mov eax, pml4
	mov cr3, eax

	; Enable PAE
	mov eax, cr4
	or eax, 1 << 5
	mov cr4, eax

	; Enable Long Mode in the MSR
	; Use this to perform some initialization of features
	; we might need
	mov ecx, 0xC0000080
	rdmsr
	or eax, 1 ; enable syscall/sysret
	or eax, 1 << 8 ; enable long mode
	or eax, 1 << 11 ; enable NX
	wrmsr

	; Enable Paging
	mov eax, cr0
	or eax, 1 << 31
	mov cr0, eax

	ret
gdt:
	DQ	0x0000000000000000
	DQ	0x00CF9A000000FFFF
	DQ	0x00CF92000000FFFF
	DQ	0x0000000000000000
	DQ	0x00A09A0000000000
	DQ	0x00A0920000000000
	DQ	0x00A0FA0000000000
	DQ	0x00A0F20000000000
global tss_gdt
tss_gdt:
	DW	0x67,0
	DB	0, 0xE9, 0
	DB	0
	DD	0

gdtr1:
	DW	40
	DD	gdt

gdtr2:
	DW	40
	DD	gdt + 24
	DD	0

gdtr3:
	DW	56
	DQ	gdt + 24 + 0xFFFFFFFF80000000
section .bss
global tss
tss:
	resb 4096
