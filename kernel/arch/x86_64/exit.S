/*
 * Copyright (c) 2016 - 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <onyx/registers.h>
#include <onyx/x86/segments.h>
#include <onyx/x86/asm.h>

#define REGISTERS_UNUSED_OFF		16

.macro popaq
    pop %r15
    pop %r14
    pop %r13
    pop %r12
    pop %r11
    pop %r10
    pop %r9
    pop %r8
    pop %rbp
    pop %rsi
    pop %rdi
    pop %rdx
    pop %rcx
    pop %rbx
    pop %rax
.endm

.macro INTERRUPT_STACK_ALIGN
    /* After pushing the interrupt frame we're left with an 8-byte aligned stack,
     * so align it by subbing 8 bytes
    */
    sub $8, %rsp
.endm

.macro INTERRUPT_STACK_RESTORE
    add $8, %rsp
.endm

.text
ENTRY(__cxa_atexit)
    # NOTE: We can do this with __cxa_atexit because we, as the kernel, will never exit!
    xor %eax, %eax
    RET
END(__cxa_atexit)

/* extern "C" 
[[noreturn]]
void x86_context_switch(thread *prev **%rdi** , unsigned char *stack **%rsi**);
*/
ENTRY(x86_context_switch)
    cli
    /* First thing to do: switch the %rsp */
    /* Then we can try to release the thread */
    mov %rsi, %rsp
    INTERRUPT_STACK_ALIGN
    /* note that prev is already in %rdi, no need to move it in */
    /* We also don't need to preserve any registers */
    call finish_switch
    jmp x86_interrupt_ret
END(x86_context_switch)
