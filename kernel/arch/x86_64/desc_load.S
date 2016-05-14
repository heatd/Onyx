section .text
global GDT_Flush
GDT_Flush:
	mov rax,rdi
	lgdt [rax]

	push 08h
	push .flush
	retf
.flush:
	mov ax, 10h      ; 0x10 is the offset in the GDT to our data segment
	mov ds, ax        ; Load all data segment selectors
	mov es, ax
	mov fs, ax
	mov gs, ax
	mov ss, ax
	ret
global IDT_Flush
IDT_Flush:
	mov rax,rdi
	lidt [rax]
	ret
