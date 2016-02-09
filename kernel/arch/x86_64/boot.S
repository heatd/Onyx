;Copyright 2016 Pedro Falcato
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
[BITS 32]
[SECTION .mbhdr]
[EXTERN _loadStart]
[EXTERN _loadEnd]
[EXTERN _bssEnd]

ALIGN 8
MbHdr:
	; Magic
	DD	0xE85250D6
	; Architecture
	DD	0
	; Length
	DD	HdrEnd - MbHdr
	; Checksum
	DD	-(0xE85250D6 + 0 + (HdrEnd - MbHdr))

	;
	; Tags
	;
	; Sections override
	DW	2, 0
	DD	24
	DD	MbHdr
	DD	_loadStart
	DD	_loadEnd
	DD	_bssEnd
	align 8
	; Entry point override
	DW	3, 0
	DD	12
	DD	EntryPoint
	align 8
	; End Of Tags
	DW	0, 0
	DD	8

	; Hdr End Mark
HdrEnd:

[SECTION .boot]
[GLOBAL EntryPoint]
EntryPoint:
	push eax
	push ebx
	mov eax, Gdtr1
	lgdt [eax]

	push 0x08
	push .GdtReady
	retf

.GdtReady:
	mov eax, 0x10
	mov ds, ax
	mov ss, ax

	call SetupPagingAndLongMode

	mov eax, Gdtr2
	lgdt [Gdtr2]

	push 0x08
	push .Gdt2Ready
	retf

[BITS 64]
.Gdt2Ready:
	mov eax, 0x10
	mov ds, ax
	mov es, ax
	mov ss, ax

	; If you later decide to unmap the lower zone, you will have an invalid Gdt if you're still using Gdtr2
	mov rax, Gdtr3
	lgdt [rax]
	pop rbx
	pop rax
	mov rdi, rbx
	mov rsi, rax
	mov rax, _start
	jmp rax
section .bootstrap_stack, nobits
align 4
stack_bottom:
resb 16384
stack_top:
section .text
extern KernelEarly
extern KernelMain
_start:
	cli
	pop rax
	pop rbx
	mov rdi,rax
	mov rsi,rbx
	mov rsp, stack_top
	call KernelEarly
	call KernelMain
	cli
.Lhang:
	hlt
	jmp .Lhang
section .boot
[BITS 32]
[EXTERN Pml4]
[EXTERN Pdpt]
[EXTERN Pd]
SetupPagingAndLongMode:
	mov eax, Pdpt
	or eax, 1
	mov [Pml4], eax
	mov [Pml4 + 0xFF8], eax

	mov eax, Pd
	or eax, 1
	mov [Pdpt], eax
	mov [Pdpt + 0xFF0], eax

	mov dword [Pd], 0x000083
	mov dword [Pd + 8], 0x200083
	mov dword [Pd + 16], 0x400083
	mov dword [Pd + 24], 0x600083

	; Load CR3 with PML4
	mov eax, Pml4
	mov cr3, eax

	; Enable PAE
	mov eax, cr4
	or eax, 1 << 5
	mov cr4, eax

	; Enable Long Mode in the MSR
	mov ecx, 0xC0000080
	rdmsr
	or eax, 1 << 8
	wrmsr

	; Enable Paging
	mov eax, cr0
	or eax, 1 << 31
	mov cr0, eax

	ret

TmpGdt:
	DQ	0x0000000000000000
	DQ	0x00CF9A000000FFFF
	DQ	0x00CF92000000FFFF
	DQ	0x0000000000000000
	DQ	0x00A09A0000000000
	DQ	0x00A0920000000000

Gdtr1:
	DW	23
	DD	TmpGdt

Gdtr2:
	DW	23
	DD	TmpGdt + 24
	DD	0

Gdtr3:
	DW	23
	DQ	TmpGdt + 24 + 0xFFFFFFFF80000000
 
