/*
 * Copyright (c) 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

/* ssize_t copy_to_user_internal(void *user, const void *data, size_t size); */
.global copy_to_user_internal
.type copy_to_user_internal,@function
copy_to_user_internal:
    mov x3, x0
    mov x0, xzr
    /* x2 = limit, x3 = user, x1 = data, x0 = 0 */
    cbz x2, 3f
    add x2, x3, x2
1:
    ldrb w4, [x1], #1
2:
    strb w4, [x3], #1
    cmp x2, x3
    bne 1b
3:
    ret
4:
    mov x0, -14
    ret

.pushsection .ehtable
    .dword 2b
    .dword 4b
.popsection


/* ssize_t copy_from_user_internal(void *data, const void *usr, size_t size); */
.global copy_from_user_internal
.type copy_from_user_internal,@function
copy_from_user_internal:
    mov x3, x0
    mov x0, xzr
    /* x2 = limit, x3 = user, x1 = data, x0 = 0 */
    cbz x2, 3f
    add x2, x3, x2
1:
    ldrb w4, [x1], #1
    strb w4, [x3], #1
    cmp x2, x3
    bne 1b
3:
    ret
4:
    mov x0, -14
    ret

.pushsection .ehtable
    .dword 1b
    .dword 4b
.popsection

/* ssize_t user_memset_internal(void *data, int val, size_t len); */
.global user_memset_internal
.type user_memset_internal,@function
user_memset_internal:
    and w1, w1, 0xff
    cbz x2, 3f
    add x2, x0, x2
1:
    strb w1, [x0], #1
    cmp x2, x0
    bne 1b
3:
    mov x0, xzr
    ret
4:
    mov x0, -14
    ret

.pushsection .ehtable
    .dword 1b
    .dword 4b
.popsection

/* ssize_t strlen_user_internal(const char *user); */
.global strlen_user_internal
.type strlen_user_internal,@function
strlen_user_internal:
    mov x1, x0
    mov x0, xzr
1:
    ldrb w2, [x1], #1
    cbz w2, 2f
    add x0, x0, 1
    b 1b
2:
    ret 
4:
    mov x0, -14
    ret

.pushsection .ehtable
    .dword 1b
    .dword 4b
.popsection
