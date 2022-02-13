/*
 * Copyright (c) 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

# ssize_t copy_to_user_internal(void *user, const void *data, size_t size);
.global copy_to_user_internal
.type copy_to_user_internal,@function
copy_to_user_internal:
    li a4, 1 << 18
    csrs sstatus, a4
    beqz a2, 3f
1:
    lb a3, 0(a1)
    addi a1, a1, 1
2:  sb a3, 0(a0)
    addi a0, a0, 1
    addi a2, a2, -1
    bnez a2, 1b
3:
    mv a0, zero
    csrc sstatus, a4
    ret

.pushsection .ehtable
    .dword 2b
    .dword out_user_efault
.popsection

# ssize_t copy_from_user_internal(void *data, const void *usr, size_t size);
.global copy_from_user_internal
.type copy_from_user_internal,@function
copy_from_user_internal:
    li a4, 1 << 18
    csrs sstatus, a4
    beqz a2, 3f
1:
    lb a3, 0(a1)
    addi a1, a1, 1
    sb a3, 0(a0)
    addi a0, a0, 1
    addi a2, a2, -1
    bnez a2, 1b
3:
    mv a0, zero
    csrc sstatus, a4
    ret

.pushsection .ehtable
    .dword 1b
    .dword out_user_efault
.popsection

# ssize_t user_memset_internal(void *data, int val, size_t len);
.global user_memset_internal
.type user_memset_internal,@function
user_memset_internal:
    li a4, 1 << 18
    csrs sstatus, a4
    beqz a2, 3f
1:
    sb a1, 0(a0)
    addi a0, a0, 1
    addi a2, a2, -1
    bnez a2, 1b
3:
    mv a0, zero
    csrc sstatus, a4
    ret

.pushsection .ehtable
    .dword 1b
    .dword out_user_efault
.popsection

out_user_efault:
    li a0, -14
    # a4 = (1 << 18) - permit supervisor user memory access
    # We use it when setting and now when clearing
    csrc sstatus, a4
    ret

# ssize_t strlen_user_internal(const char *user);
.global strlen_user_internal
.type strlen_user_internal,@function
strlen_user_internal:
    li a4, 1 << 18
    csrs sstatus, a4
    # a1 is our counter here
    mv a1, zero

    # Slow, maybe port x86's strlen_user to riscv?
1:  lb a2, 0(a0)
    beqz a2, 2f
    addi a1, a1, 1
    addi a0, a0, 1
    j 1b
2:
    mv a0, a1
    csrc sstatus, a4
    ret

.pushsection .ehtable
    .dword 1b
    .dword out_user_efault
.popsection
