section .text
BITS 16
global _start_smp
extern smp_done
_start_smp:
	cli ;ensure that interrupts are disabled
	xor ax, ax
	mov ds, ax
	mov gs, ax
	mov fs, ax
	mov es, ax
	mov ss, ax
	mov cr0, eax
	lgdt [0x0 + (_gdtr_begin - _start_smp)]
	mov eax, cr0
	or al, 1
	mov cr0, eax
__long_mode_enter:
	extern pml4
	;Load the kernel's pml4
	mov eax, pml4
	mov cr3, eax
	;Enable PAE
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
	lgdt [0x0 + (_gdtr2_begin - _start_smp)]
	mov esp, (stack - _start_smp)
	push 0x08
	push 0x0 + (_long_mode - _start_smp)
	retf
_long_mode:
BITS 64
	mov eax, 0x10
	mov ds, ax
	mov es, ax
	mov ss, ax
	mov gs, ax
	mov fs, ax
	extern ap_done
	; Load the common gdt between all cores
	extern gdtr3
	lgdt [gdtr3]
	extern idt_ptr
	lidt [idt_ptr]
	extern core_stack
	mov rsp, [core_stack]
	mov rax, cr3
	mov cr3, rax
	
	mov rax, cr0
	and ax, 0xFFFB
	or ax, 0x2
	mov cr0, rax
	mov rax, cr4
	or ax, 3 << 9
	mov cr4, rax
	; Say to the BSP that we finished
	extern ap_done
	lock inc byte [ap_done]
halt:
	hlt
	jmp halt
align 16
stack: resb 512
global _smp_func_end
_smp_func_end:
gdt:
	DQ	0x0000000000000000
	DQ	0x00CF9A000000FFFF
	DQ	0x00CF92000000FFFF
gdtl:
	DQ 	0x0000000000000000
	DQ	0x00A09A0000000000
	DQ	0x00A0920000000000
	DQ	0x00A0FA0000000000
	DQ	0x00A0F20000000000
tss_gdt:
	DW	0x67,0
	DB	0, 0xE9, 0
	DB	0
	DD	0

_gdtr_begin:
gdtr:
	DW	40
	DD	0x0 + (_smp_func_end - _start_smp)
_gdtr2_begin:
gdtr2:
	DW 40
	DD 0x0 + (gdtl - _start_smp)
global _end_smp
_end_smp:
section .text
global __idle
__idle:
	cli
	hlt
	jmp __idle