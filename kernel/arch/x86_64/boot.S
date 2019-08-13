#
# Copyright (c) 2016, 2017 Pedro Falcato
# This file is part of Onyx, and is released under the terms of the MIT License
# check LICENSE at the root directory for more information
#

.section .boot
.align 4
hdr_start: 
        .long 0xe85250d6
        .long 0
        .long hdr_end - hdr_start
        .long 0x100000000 - (0xe85250d6 + 0 + (hdr_end - hdr_start))
        .align 8 # All tags need to be 8 byte aligned
        # Framebuffer tag
        .word 5
        .word 0
        .long 20
        .long 1024
        .long 768
        .long 32
        .align 8
        # Module alignment tag
        .word 6
        .word 0
        .long 8
        .align 8
        # Finish tag
        .word 0
        .word 0
        .long 8
hdr_end: 

.section .bootstrap_stack
.align 4
stack_bottom:
.skip 16384
stack_top:

.section .text
_start: 
        push $0
        movq $stack_top, %rsp
        call initsse
        call kernel_early
        call _init
        call randomize_stack_canary
        call kernel_main
        cli
_start.Lhang: 
        hlt
        jmp _start.Lhang

.data
.text
.global initsse
initsse: 
        movq $0x1, %rax
        cpuid
        testl $1<<25, %edx
        jz initsse.no_sse
        movq %cr0, %rax
        andw $0xFFFB, %ax
        orw $0x2, %ax
        or $1 << 16, %eax
        movq %rax, %cr0
        movq %cr4, %rax
        or $3 << 9, %ax
        or $1 << 18, %eax
        movq %rax, %cr4
        # Use 0x1F80, because it's the default and it looks reasonable
        push $0x1F80
        ldmxcsr (%rsp)
        addq $8, %rsp
        ret
initsse.no_sse: 
        ud2

.section .boot
protectedmode_stack:
        .skip 32
protectedmode_stack_top:

.code32
.global entry_point
entry_point: 
        cli
        # Clear the direction flag since its state is unspecified by the multiboot spec
        cld
        mov $protectedmode_stack_top, %esp
        pushl %eax
        pushl %ebx
        movl $gdtr1, %eax
        lgdt (%eax)

        pushl $0x08
        push $.gdtrdy
        lret

.gdtrdy: 
        movl $0x10,%eax
        movw %ax,%ds
        movw %ax,%ss
        call setup_paging_and_longm

        movl $gdtr2, %eax
        lgdt (gdtr2)

        pushl $0x08
        push $.gdt2rdy
        lret

.code64
.gdt2rdy: 
        movl $0x10,%eax
        movw %ax,%ds
        movw %ax,%es
        movw %ax,%ss

        movq $gdtr3, %rax
        lgdt (%rax)
        popq %rbx
        xorq %rsi,%rsi
        movq %rbx,%rsi
        shrq $32,%rsi

        movq %rbx, %r8
        xorq %rdi,%rdi
        movl %r8d, %edi
        movq $_start, %rax
        jmp *%rax

.code32
setup_paging_and_longm: 
        movl $pdpt, %eax
        orl $3,%eax
        or $1 << 2, %eax
        movl %eax,pml4
        mov %eax, pml4 + 0xFF8
        movl $pdlower, %eax
        orl $3, %eax
        or $1 << 8, %eax
        or $1 << 2, %eax
        movl %eax, pdpt
        movl $pd, %eax
        orl $3, %eax
        or $1 << 8, %eax
        or $1 << 2, %eax
        mov %eax, pdpt + 0xFF0

        movl $0x000083, pd
        orl $1 << 8, pd
        movl $0x200083, pd + 8
        orl $1 << 8, pd + 8
        movl $0x400083, pd + 16
        orl $1 << 8, pd + 16

        /*movl $0x1000083, pd + 64
        orl $1 << 8, pd + 64
        movl $0x1200083, pd + 72
        orl $1 << 8, pd + 72
        movl $0x1400083, pd + 80
        orl $1 << 8, pd + 80*/

        movl $0x000083, pdlower + 0
        orl $1 << 8, pdlower + 0
        movl $0x200083, pdlower + 8
        orl $1 << 8, pdlower + 8

        # Load CR3 with PML4
        movl $pml4, %eax
        movl %eax, %cr3

        # Enable PAE
        movl %cr4, %eax
        or $1 << 5, %eax
        movl %eax, %cr4

        # Enable Long Mode in the MSR
        # Use this to perform some initialization of features
        # we might need
        movl $0xC0000080, %ecx
        rdmsr
        # enable syscall/sysret
        orl $1, %eax
        or $1 << 8, %eax
        or $1 << 11, %eax
        xorl %edx,%edx
        wrmsr

        # Enable Paging
        movl %cr0, %eax
        or $1 << 31, %eax
        movl %eax, %cr0

        ret
gdt: 
        .quad 0x0000000000000000
        .quad 0x00CF9A000000FFFF
        .quad 0x00CF92000000FFFF
gdt_begin: 
        .quad 0x0000000000000000   # 0x0  - NULL segment
        .quad 0x00A09A0000000000   # 0x8  - KERNEL CS
        .quad 0x00A0920000000000   # 0x10 - KERNEL DS
        .quad 0x00CFFA000000FFFF   # 0x18 - 32-bit user CS
        .quad 0x00CFF2000000FFFF   # 0x20 - 32-bit user DS
        .quad 0x00A0FA0000000000   # 0x28 - USER CS
        .quad 0x00A0F20000000000   # 0x30 - USER DS
.global tss_gdt                    # 0x38 - TSS
tss_gdt: 
        .word 0x67,0
        .byte 0,0xE9,0
        .byte 0
        .long 0
gdt_end: 
gdtr1: 
        .word 40
        .long gdt

gdtr2: 
        .word 76
        .long gdt_begin
        .long 0

.global gdtr3
gdtr3: 
        .word 76
        .quad gdt_begin + 0xFFFFFFFF80000000

.bss
.global tss
tss: 
.skip 4096

