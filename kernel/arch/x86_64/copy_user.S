/*
 * Copyright (c) 2019 - 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#include <onyx/x86/alternatives.h>
#include <onyx/x86/asm.h>

/**
 * @brief Copies data to user space.
 * 
 * @param usr The destination user space pointer.
 * @param data The source kernel pointer.
 * @param len The length of the copy, in bytes.
 * @return 0 if successful, negative error codes if error'd.
 *         At the time of writing, the only possible error return is -EFAULT.
 */
# ssize_t copy_to_user(void *user, const void *data, size_t size);
.section .text
.balign 32
ENTRY(copy_to_user)
    # Note: This is slow, but it's needed...
    # TODO: How can we access C structs from assembly safely?
    push %rdi
    push %rsi
    push %rdx

    call thread_get_addr_limit
    
    pop %rdx
    pop %rsi
    pop %rdi

    # Check if dst < addr_limit
    cmp %rax, %rdi
    # And if dst + len < addr_limit
    mov %rdi, %r8
    add %rdx, %r8
    cmp %rax, %r8

    ja 3f
    xor %rax, %rax
    mov %rdx, %rcx
    __ASM_ALTERNATIVE_INSTRUCTION(x86_smap_stac_patch, 3, 0, 0)
1:
    rep movsb (%rsi), (%rdi)
2:
    __ASM_ALTERNATIVE_INSTRUCTION(x86_smap_clac_patch, 3, 0, 0)
    RET
3:
    # CBN_STATUS_SEGFAULT = -5
    # These pieces of code were ported from Carbon but the principle applies
    # We're returning -EFAULT = -14
    mov $-14, %rax
    jmp 2b

.pushsection .ehtable
    .quad 1b
    .quad 3b
.popsection
END(copy_to_user)

/**
 * @brief Copies data from user space.
 * 
 * @param data The destionation kernel pointer.
 * @param usr The source user space pointer.
 * @param len The length of the copy, in bytes.
 * @return 0 if successful, negative error codes if error'd.
 *         At the time of writing, the only possible error return is -EFAULT.
 */
# ssize_t copy_from_user(void *data, const void *usr, size_t size);
.balign 32
ENTRY(copy_from_user)
    # Note: This is slow, but it's needed...
    # TODO: How can we access C structs from assembly safely?
    push %rdi
    push %rsi
    push %rdx

    call thread_get_addr_limit
    
    pop %rdx
    pop %rsi
    pop %rdi

    # Check if src < addr_limit
    cmp %rax, %rsi
    # And if src + len < addr_limit
    mov %rsi, %r8
    add %rdx, %r8
    cmp %rax, %r8

    ja 3f
    xor %rax, %rax
    mov %rdx, %rcx
    __ASM_ALTERNATIVE_INSTRUCTION(x86_smap_stac_patch, 3, 0, 0)
1:
    rep movsb (%rsi), (%rdi)
2:
    __ASM_ALTERNATIVE_INSTRUCTION(x86_smap_clac_patch, 3, 0, 0)
    RET
3:
    # CBN_STATUS_SEGFAULT = -5
    mov $-14, %rax
    jmp 2b

.pushsection .ehtable
    .quad 1b
    .quad 3b
.popsection
END(copy_from_user)

.balign 32
ENTRY(strlen_user)
    # Note: This is slow, but it's needed...
    # TODO: How can we access C structs from assembly safely?
    push %rdi

    call thread_get_addr_limit
    
    pop %rdi

    # Check if src < addr_limit
    cmp %rax, %rdi

    ja 7f

    xor %rax, %rax
    /* Basically we want do to here what we do in strlen(), we're using a
     * HASZERO kind of thing while aligning the string first to a word boundary. */

    /* For reference:
     #define CONST1          ((size_t) 0x0101010101010101ULL)
     #define CONST2          ((size_t) 0x8080808080808080ULL)

     #define WORD_SIZE           (sizeof(size_t))
     #define ALIGNED(x, y)       !((unsigned long) x & (y - 1))
     #define HASZERO(v)          (((v) - CONST1) & ~(v) & CONST2)
    */
    __ASM_ALTERNATIVE_INSTRUCTION(x86_smap_stac_patch, 3, 0, 0)
1:
    test $7, %rdi
    jz 5f

4:
    cmpb $0, (%rdi)
    jz 6f

    /* We also need to increment %rax here */
    inc %rax
    inc %rdi

    jmp 1b

5:
    movabs $0x0101010101010101, %rsi
    movabs $0x8080808080808080, %rdx

    /* Read the word and keep two copies of it: one will be subbed from and the
     * other will be NOT'd */
2:
    mov (%rdi), %r8
    mov %r8, %rcx

    sub %rsi, %r8
    not %rcx
    and %rcx, %r8
    and %rdx, %r8

    jnz 3f

    add $8, %rax
    add $8, %rdi

    jmp 2b

    /* This is the good ol' for-loop-based strlen that we're using here to search these 8 bytes */
3:
    cmpb $0, (%rdi)
    je 6f
    inc %rax
    inc %rdi
    jmp 3b

6:
    __ASM_ALTERNATIVE_INSTRUCTION(x86_smap_clac_patch, 3, 0, 0)
    RET
7:
    # CBN_STATUS_SEGFAULT = -5
    mov $-14, %rax
    jmp 6b

.pushsection .ehtable
    .quad 2b
    .quad 7b
    .quad 3b
    .quad 7b
    .quad 4b
    .quad 7b
.popsection

END(strlen_user)

ENTRY(get_user32)
    # addr in %rdi, dest in %rsi, ret is 0 if good or -EFAULT if we faulted
    push %rdi
    push %rsi

    call thread_get_addr_limit

    pop %rsi	
    pop %rdi

    # Check if src < addr_limit
    cmp %rax, %rdi
    ja 3f
    __ASM_ALTERNATIVE_INSTRUCTION(x86_smap_stac_patch, 3, 0, 0)
1:  movl (%rdi), %edx
    movl %edx, (%rsi)
    xor %rax, %rax
2:
    __ASM_ALTERNATIVE_INSTRUCTION(x86_smap_clac_patch, 3, 0, 0)
    RET
3:
    mov $-14, %rax
    jmp 2b
.pushsection .ehtable
    .quad 1b
    .quad 3b
.popsection

END(get_user32)

ENTRY(get_user64)
    # addr in %rdi, dest in %rsi, ret is 0 if good or -EFAULT if we faulted
    push %rdi
    push %rsi

    call thread_get_addr_limit

    pop %rsi	
    pop %rdi

    # Check if src < addr_limit
    cmp %rax, %rdi
    ja 3f
    __ASM_ALTERNATIVE_INSTRUCTION(x86_smap_stac_patch, 3, 0, 0)
1:  movq (%rdi), %rdx
    movq %rdx, (%rsi)
    xor %rax, %rax
2:
    __ASM_ALTERNATIVE_INSTRUCTION(x86_smap_clac_patch, 3, 0, 0)
    RET
3:
    mov $-14, %rax
    jmp 2b
.pushsection .ehtable
    .quad 1b
    .quad 3b
.popsection
END(get_user64)

/**
 * @brief Memsets user spce memory.
 * 
 * @param data The destionation user space pointer.
 * @param data The destionation kernel pointer.
 * @param len The length of the copy, in bytes.
 * @return 0 if successful, negative error codes if error'd.
 *         At the time of writing, the only possible error return is -EFAULT.
 */
# ssize_t user_memset(void *data, int val, size_t len);
.balign 32
ENTRY(user_memset)
    push %rdi
    push %rsi
    push %rdx

    call thread_get_addr_limit
    
    pop %rdx
    pop %rsi
    pop %rdi

    # Check if dst < addr_limit
    cmp %rax, %rdi
    # And if dst + len < addr_limit
    mov %rdi, %r8
    add %rdx, %r8
    cmp %rax, %r8

    ja 3f
    mov %si, %ax
    mov %rdx, %rcx
    xor %rax, %rax

    __ASM_ALTERNATIVE_INSTRUCTION(x86_smap_stac_patch, 3, 0, 0)
1:
    rep stosb (%rdi)
2:
    __ASM_ALTERNATIVE_INSTRUCTION(x86_smap_clac_patch, 3, 0, 0)
    RET
3:
    # CBN_STATUS_SEGFAULT = -5
    # These pieces of code were ported from Carbon but the principle applies
    # We're returning -EFAULT = -14
    mov $-14, %rax
    jmp 2b

.pushsection .ehtable
    .quad 1b
    .quad 3b
.popsection
END(user_memset)
