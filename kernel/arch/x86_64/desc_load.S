/*
 Copyright (c) 2016, 2017 Pedro Falcato
 This file is part of Onyx, and is released under the terms of the MIT License
 check LICENSE at the root directory for more information
*/
.section .text
.global tss_flush
tss_flush:
	mov $0x3b, %ax
	ltr %ax
	ret
.global gdt_flush
gdt_flush:
	lgdt (%rdi)
	ret
.global idt_flush
idt_flush:
	lidt (%rdi)
	ret
