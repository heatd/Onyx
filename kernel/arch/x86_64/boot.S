/*
 * Copyright (c) 2016 - 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#include <onyx/x86/asm.h>
#include <onyx/x86/control_regs.h>
#include <onyx/x86/msr.h>
#include <onyx/x86/segments.h>

#define KERNEL_VIRTUAL_BASE     0xffffffff80000000
#define X86_PAGING_PRESENT		(1 << 0)
#define X86_PAGING_WRITE		(1 << 1)
#define X86_PAGING_USER			(1 << 2)
#define X86_PAGING_WRITETHROUGH		(1 << 3)
#define X86_PAGING_PCD			(1 << 4)
#define X86_PAGING_ACCESSED		(1 << 5)
#define X86_PAGING_DIRTY		(1 << 6)
#define X86_PAGING_PAT			(1 << 7)
#define X86_PAGING_HUGE			(1 << 7)
#define X86_PAGING_GLOBAL		(1 << 8)
#define X86_PAGING_NX			(1 << 63)

#define IMAGE_FILE_MACHINE_AMD64 0x8664

#define IMAGE_FILE_RELOCS_STRIPPED    0x1
#define IMAGE_FILE_EXECUTABLE_IMAGE   0x2
/* These next 2 are deprecated and should be zero */
#define IMAGE_FILE_LINE_NUMS_STRIPPED 0x4
#define IMAGE_FILE_LOCAL_SYMS_STRIPPED 0x8
#define IMAGE_FILE_AGGRESSIVE_WS_TRIM 0x10
#define IMAGE_FILE_LARGE_ADDRESS_AWARE 0x20
/* deprecated, sbz */
#define IMAGE_FILE_BYTES_REVERSED_LO 0x80
#define IMAGE_FILE_32BIT_MACHINE 0x100
#define IMAGE_FILE_DEBUG_STRIPPED 0x200
#define IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP 0x400
#define IMAGE_FILE_NET_RUN_FROM_SWAP 0x800
#define IMAGE_FILE_SYSTEM  0x1000
#define IMAGE_FILE_DLL 0x2000
#define IMAGE_FILE_UP_SYSTEM_ONLY 0x4000
#define IMAGE_FILE_BYTES_REVERSED_HI 0x8000  

#define OPTIONAL_HEADER_PE32 0x10b
#define OPTIONAL_HEADER_PE32PLUS 0x20b

#define IMAGE_SUBSYSTEM_EFI_APPLICATION  10

#define PAGE_SIZE 4096

#define IMAGE_SCN_CNT_CODE 0x20
#define IMAGE_SCN_CNT_INITIALIZED_DATA 0x40
#define IMAGE_SCN_CNT_UNINITIALIZED_DATA 0x80
#define IMAGE_SCN_MEM_EXECUTE 0x20000000
#define IMAGE_SCN_MEM_READ 0x40000000
#define IMAGE_SCN_MEM_WRITE 0x80000000

/* Note: .boot gets stuck to as close to the start of the image as possible.
 * When dealing with a flat binary (CONFIG_EFISTUB, etc), it is literally the start,
 * hence dos_header just working.
 */
.section .boot, "ax"

#ifdef CONFIG_EFISTUB
dos_header:
    .ascii "MZ"
    .skip 0x3c - 2
    .word pe_header - dos_header
.align 4
pe_header:
    .ascii "PE\0\0"
    .word IMAGE_FILE_MACHINE_AMD64
    .word 2 /* Nr sections */
    .long 0
    .long 0
    .long 0
    .word optional_header_end - optional_header
    .word IMAGE_FILE_RELOCS_STRIPPED | IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_DEBUG_STRIPPED | IMAGE_FILE_LINE_NUMS_STRIPPED
optional_header:
    .word OPTIONAL_HEADER_PE32PLUS
    /* Linker major and minor */
    .byte 0
    .byte 4
    /* Sizeof code */
    .long _ro_end - (efi_entry + KERNEL_VIRTUAL_BASE)
    /* sizeof initialized data */
    .long __pecoff_data_size
    /* sizeof uninitialized data */
    .long _bss_size
    /* entry point */
    .long efi_entry - dos_header
    /* BaseOfCode */
    .long efi_entry - dos_header
windows_header:
    /* Image base */
    .quad 0x1000000
    /* SectionAlignment */
    .long PAGE_SIZE
    /* FileAlignment */
    .long PAGE_SIZE /* ?? */
    /* Various version crap */
    .word 0
    .word 0
    /* Image version major/minor */
    .word 0
    .word 4
    /* Subsystem version */
    .word 0
    .word 0
    /* Win32VersionValue */
    .long 0
    /* SizeOfImage */
    .long kernel_phys_end - dos_header
    /* SizeOfHeaders */
    .long header_end - dos_header
    /* CheckSum */
    .long 0
    .word IMAGE_SUBSYSTEM_EFI_APPLICATION
    /* DLL characteristics */
    .word 0
    /* Stack and heap reserve - unused */
    .quad 0
    .quad 0
    .quad 0
    .quad 0
    /* LoaderFlags - mbz */
    .long 0
    /* NumberOfRvaAndSizes - unclear what this does */
    .long 6

    /* Is this related to RVA and sizes? */
    .quad 0
    .quad 0
    .quad 0
    .quad 0
    .quad 0
    .quad 0
    /* Optional header end */
optional_header_end:
    /* Section table */
section_table:
    .ascii ".text\0\0\0"
    .long _text_end - (efi_entry + KERNEL_VIRTUAL_BASE)
    .long efi_entry - dos_header
    .long _text_end - (efi_entry + KERNEL_VIRTUAL_BASE)
    /* PointerToRawData */
    .long efi_entry - dos_header
    .long 0 /* PointerToRelocations */
    .long 0 /* PointerToLineNumbers */
    .word 0 /* Number of ^^ */
    .word 0
    .long IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ
    /* .data */
    .ascii ".data\0\0\0"
    .long _data_size
    .long (_data_start - KERNEL_VIRTUAL_BASE) - dos_header
    .long __pecoff_data_size
    /* PointerToRawData */
    .long efi_entry - dos_header
    .long 0 /* PointerToRelocations */
    .long 0 /* PointerToLineNumbers */
    .word 0 /* Number of ^^ */
    .word 0
    .long IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_CNT_UNINITIALIZED_DATA
header_end:

.align PAGE_SIZE
efi_entry:
    hlt
    jmp efi_entry
#endif
jmp entry_point
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
#ifdef CONFIG_RELOCATABLE_PHYS
    .align 8
    .word 10
    .word 0
    .long 24
    /* Use a minimum address of 16MiB, a max of 4GiB, alignment of 2MiB (so we can easily map ourselves) */
    .long 0x1000000
    .long 0xffffffff
    .long 0x200000
    /* 2 = put us as high as you can */
    .long 2
#endif
    .align 8
    # Finish tag
    .word 0
    .word 0
    .long 8
hdr_end: 

.section .bss

#ifdef CONFIG_KASAN
.align 8 * 16384
#else
.align 16
#endif

.global x86_stack_bottom
x86_stack_bottom:
.skip 16384

x86_stack_top:

.section .text
_start:
    movq $x86_stack_top, %rsp
    pushq $0
    mov %rsp, %rbp

    /* Take the time to wrmsr the default GS_BASE */
    mov $percpu_base, %rdx
    mov %rdx, %r11
    mov %edx, %eax
    shr $32, %rdx
    mov $GS_BASE_MSR, %ecx
    wrmsr

    mov %r11, %gs:__cpu_base

    push %rdi
    push %rsi

#ifdef CONFIG_KASAN
    call x86_bootstrap_kasan
#endif
    pop %rsi
    pop %rdi

    call multiboot2_kernel_entry
    call _init
    call runtime_call_constructors
    # rdi = cpu nr
    xor %rdi, %rdi
    call init_ssp_for_cpu
    call kernel_main
    cli
_start.Lhang: 
    hlt
    jmp _start.Lhang

.section .boot, "ax"
protectedmode_stack:
    .skip 128
protectedmode_stack_top:

#ifdef CONFIG_RELOCATABLE_PHYS
#define CALC_EFF_ADDRESS(label, reg) lea label(%ebp), reg
#else
#define CALC_EFF_ADDRESS(label, reg) mov $label, reg
#endif

.code32
.global entry_point
entry_point:
    cli
#ifdef CONFIG_RELOCATABLE_PHYS
    /* Calculate a possible load bias */
    call 1f
1:
    pop %edi
    movl $1b, %ebp
    sub %ebp, %edi
    mov %edi, %ebp
#else
    xor %ebp, %ebp
#endif
    /* From now on, ebp = load bias */
    # Clear the direction flag since its state is unspecified by the multiboot spec
    cld
    CALC_EFF_ADDRESS(protectedmode_stack_top, %esp)
    pushl %eax
    pushl %ebx
    CALC_EFF_ADDRESS(gdtr1, %eax)
    # Fix up the gdtr before loading it
    CALC_EFF_ADDRESS(gdt, %ebx)
    mov %ebx, 2(%eax)
    lgdt (%eax)

    pushl $0x08
    CALC_EFF_ADDRESS(.gdtrdy, %eax)

    push %eax
    lret

.gdtrdy: 
    movl $0x10, %eax
    movw %ax, %ds
    movw %ax, %ss
    call setup_paging_and_longm

    CALC_EFF_ADDRESS(gdtr2, %eax)
    /* Fixup the gdtr2's gdt address */
    CALC_EFF_ADDRESS(gdt_begin, %edi)
    mov %edi, 2(%eax)
    lgdt (%eax)

    pushl $0x08
    CALC_EFF_ADDRESS(.gdt2rdy, %eax)
    push %eax
    lret

.code64
.gdt2rdy:
    movl $0x10, %eax
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %ss

    # Our %gs and %fs segments need to be NULL
    xor %ax, %ax
    mov %ax, %gs
    mov %ax, %fs

    lea gdtr3(%rip), %rax
    lgdt (%rax)
    popq %rbx
    xorq %rsi, %rsi
    movq %rbx, %rsi
    shrq $32, %rsi

    movq %rbx, %r8
    xorq %rdi, %rdi
    movl %r8d, %edi
#ifdef CONFIG_RELOCATABLE_PHYS
    mov %rbp, kernel_phys_offset
#endif
    movq $_start, %rax
    jmp *%rax

.macro PAGE_TABLE_INDEX source_ptr, level

mov $\level * 9, %cl
mov 4(\source_ptr), %esi
mov (\source_ptr), %ebx
shrdl %esi, %ebx
and $0x1ff, %ebx

.endm

.code32

zero_page_tables:
    CALC_EFF_ADDRESS(__early_page_tables_start, %edi)
    mov $__early_page_tables_size, %ecx
    xor %al, %al
    rep stosb
    ret

setup_paging_and_longm:
    /* Register allocation:
     * edi - Top level page table
     * 
     * Usual register allocation for the rest of the code:
     * eax - Page table entry
     * ecx - Page table index
     * edx - shift amount
     *
     * Stack allocation:
     * [off 0] = virtual pfn low
     * [off 4] =  virtual pfn high
     */
    
    call zero_page_tables

    sub $8, %esp
    # Index formula: (virt >> 12) >> (pt_level * 9) & 0x1ff;

    mov $KERNEL_VIRTUAL_BASE >> 32, %ebx
    movl $KERNEL_VIRTUAL_BASE, %ecx
    add $PHYS_BASE, %ecx
    shrdl $12, %ebx, %ecx
    shr $12, %ebx
    mov %ecx, (%esp)
    mov %ebx, 4(%esp)

    /* The top page level is held in %edi */
    /* Test for PML5 */
    mov $7, %eax
    xor %ecx, %ecx
    cpuid
    test $1 << 16, %ecx
    jz 1f

    /* Enable PML5 on cr4 and set a flag */
    mov %cr4, %eax
    or $1 << 12, %eax
    mov %eax, %cr4
    mov $pml5, %edi

    jmp 2f
1:
    CALC_EFF_ADDRESS(pml4, %edi)
2:
    CALC_EFF_ADDRESS(pdpt, %eax)
    orl $(X86_PAGING_PRESENT | X86_PAGING_WRITE), %eax
    movl %eax, (%edi)

    PAGE_TABLE_INDEX %esp, 3

    CALC_EFF_ADDRESS(pml4, %esi)
    mov %eax, (%esi, %ebx, 8)

    /* Set up the lower page directories for the lower range of the address space */
    CALC_EFF_ADDRESS(pdlower, %eax)
    or $(X86_PAGING_PRESENT | X86_PAGING_WRITE), %eax
    CALC_EFF_ADDRESS(pdpt, %esi)
    movl %eax, (%esi)
    add $0x1000, %eax
    movl %eax, 8(%esi)
    add $0x1000, %eax
    movl %eax, 16(%esi)
    add $0x1000, %eax
    movl %eax, 24(%esi)

    CALC_EFF_ADDRESS(pd, %eax)
    or $(X86_PAGING_PRESENT | X86_PAGING_WRITE), %eax

    PAGE_TABLE_INDEX %esp, 2

    CALC_EFF_ADDRESS(pdpt, %esi)
    mov %eax, (%esi, %ebx, 8)

    PAGE_TABLE_INDEX %esp, 1

    push %ebx

    CALC_EFF_ADDRESS(pdlower, %esi)
3:

    mov %ebx, %eax
    shl $21, %eax
    or $0x83, %eax
    mov %eax, (%esi, %ebx, 8)
    inc %ebx
    cmp $2048, %ebx
    jne 3b

    pop %ebx

    push %ebp
    CALC_EFF_ADDRESS(pd, %esi)

    /* Calculate a useful load bias for mapping */
    add $PHYS_BASE, %ebp
    and $-0x200000, %ebp

    movl %ebp, %eax
    or $0x83, %eax
    mov %eax, (%esi, %ebx, 8)
    inc %ebx
    lea 0x200000(%ebp), %eax
    or $0x83, %eax
    mov %eax, (%esi, %ebx, 8)
    inc %ebx
    lea 0x400000(%ebp), %eax
    or $0x83, %eax
    mov %eax, (%esi, %ebx, 8)
    lea 0x600000(%ebp), %eax
    or $0x83, %eax
    mov %eax, (%esi, %ebx, 8)
    inc %ebx
    lea 0x800000(%ebp), %eax
    or $0x83, %eax
    mov %eax, (%esi, %ebx, 8)

    pop %ebp

    # Load CR3 with the top page level
    movl %edi, %cr3

    # Enable PAE
    movl %cr4, %eax
    or $CR4_PAE, %eax
    movl %eax, %cr4

    # Enable Long Mode in the MSR
    # Use this to enable NX as well
    movl $IA32_EFER, %ecx
    rdmsr
    or $(IA32_EFER_LME | IA32_EFER_NXE), %eax
    xorl %edx, %edx
    wrmsr

    # Enable Paging and write protect
    movl %cr0, %eax
    or $(CR0_PG | CR0_WP), %eax
    movl %eax, %cr0

    add $8, %esp

    RET

.extern pml4
.extern boot_pml4
.extern gdtr3
.extern idt_ptr
.code32
/* Load bias in %ebp, ecx:edx for the 64-bit thread stack */
.global startup_secondary_32
startup_secondary_32:
    /* Get the PML4 and load it */
    lea pml4(%ebp), %eax
    mov %eax, %cr3
    /* Enable PAE and PSE, required for 64-bit paging */
    mov %cr4, %eax
    or $(CR4_PAE | CR4_PSE), %eax
    mov %eax, %cr4

    /* Move ecx:edx to edi:esi due to us needing ecx for MSRs and not having a stack yet. */
    mov %ecx, %edi
    mov %edx, %esi

    /* Enable Long Mode in the MSR
     * Use this to enable NX as well */

    mov $IA32_EFER, %ecx
    rdmsr
    or $(IA32_EFER_LME | IA32_EFER_NXE), %eax
    xorl %edx, %edx
    wrmsr
    /* Enable Paging and write protect */
    mov %cr0, %eax
    or $(CR0_PG | CR0_WP), %eax
    mov %eax, %cr0
    lea gdtr2(%ebp), %eax
    lgdt (%eax)

    CALC_EFF_ADDRESS(protectedmode_stack_top, %esp)
    push $KERNEL_CS
    lea startup_secondary_64(%ebp), %eax
    push %eax
    lret

startup_secondary_64:
.code64
    /* Load the higher half GDT */
    lea gdtr3(%rip), %rbx
    lgdt (%rbx)
    /* Reload segments */
    mov $KERNEL_DS, %rax
    mov %ax, %ds
    mov %ax, %es
    mov %ax, %ss
    xor %ax, %ax
    mov %ax, %gs
    mov %ax, %fs

    /* Reload CS and jump to higher half in one go */
    push $KERNEL_CS
    push $1f
    lretq
.section .text
1:
    /* Load the actual current page tables */
    mov boot_pml4(%rip), %rax
    mov %rax, %cr3

    /* Load the IDT */
    lidt (idt_ptr)

    /* Load the stack from esi:edi */
    mov %edi, %esp
    shl $32, %rsi
    or %rsi, %rsp

    mov %cr3, %rax
    mov %rax, %cr3

    /* Top of stack holds gs_base */
    pop %rdi

    /* Note: This cannot be done in C++ code because LTO likes to get funky and add stack protector stuff where
     * there wasn't any, when inlining. This caused a mov %gs:0x28, reg to exist before the
     * wrmsr and init_ssp_for_cpu.
     */
    /* Take the time to wrmsr the gs base, before we enter any C/C++ code */
    mov %rdi, %rdx
    mov %rdx, %r11
    mov %edx, %eax
    shr $32, %rdx
    mov $GS_BASE_MSR, %ecx
    wrmsr

    push %rdi
    push %rsi

    /* And call init_ssp_for_cpu too! */
    movl %gs:cpu_nr, %edi
    call init_ssp_for_cpu

    pop %rsi
    pop %rdi

    jmp smpboot_main
    int3

.section .boot,"ax"

gdt: 
    .quad 0x0000000000000000
    .quad 0x00CF9A000000FFFF
    .quad 0x00CF92000000FFFF
.global gdt_begin
gdt_begin: 
    .quad 0x0000000000000000   # 0x0  - NULL segment
    .quad 0x00A09A0000000000   # 0x8  - KERNEL CS
    .quad 0x00A0920000000000   # 0x10 - KERNEL DS
    .quad 0x00CFFA000000FFFF   # 0x18 - 32-bit user CS
    .quad 0x00CFF2000000FFFF   # 0x20 - 32-bit user DS
    .quad 0x00A0FA0000000000   # 0x28 - USER CS
    .quad 0x00A0F20000000000   # 0x30 - USER DS
                               # 0x38 - TSS
tss_gdt: 
    .quad 0
    .quad 0
.global gdt_end
gdt_end:

gdtr1: 
    .word gdt_begin - gdt - 1
    .long gdt

gdtr2: 
    .word gdt_end - gdt_begin - 1
    .long gdt_begin
    .long 0

.global gdtr3
gdtr3: 
    .word gdt_end - gdt_begin - 1
    .quad gdt_begin + 0xFFFFFFFF80000000

#ifdef CONFIG_KASAN

.section .bss
.align 4096
.global kasan_shadow_page_tables
kasan_shadow_page_tables:
    .skip 4096 * 16

#endif
