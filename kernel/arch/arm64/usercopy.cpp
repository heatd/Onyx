/*
 * Copyright (c) 2022 - 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#include <errno.h>

#include <onyx/scheduler.h>
#include <onyx/types.h>
#include <onyx/user.h>
#include <onyx/vm.h>

extern "C"
{
ssize_t copy_to_user_internal(void *user, const void *data, size_t size);
ssize_t copy_from_user_internal(void *data, const void *usr, size_t size);
ssize_t user_memset_internal(void *data, int val, size_t len);
ssize_t strlen_user_internal(const char *user);
}

#define DO_USER_POINTER_CHECKS(user, size)                                       \
    const auto limit__ = thread_get_addr_limit();                                \
    if (limit__ < (unsigned long) user || limit__ < (unsigned long) user + size) \
        return -EFAULT;                                                          \
    if (size > (SSIZE_MAX))                                                      \
        return -EFAULT;

#define DO_USER_POINTER_CHECK_NO_SIZE(user)       \
    const auto limit__ = thread_get_addr_limit(); \
    if (limit__ < (unsigned long) user)           \
        return -EFAULT;

/**
 * @brief Copies data to user space.
 *
 * @param usr The destination user space pointer.
 * @param data The source kernel pointer.
 * @param len The length of the copy, in bytes.
 * @return 0 if successful, negative error codes if error'd.
 *         At the time of writing, the only possible error return is -EFAULT.
 */
ssize_t copy_to_user(void *user, const void *data, size_t size)
{
    DO_USER_POINTER_CHECKS(user, size);
    return copy_to_user_internal(user, data, size);
}

/**
 * @brief Copies data from user space.
 *
 * @param data The destionation kernel pointer.
 * @param usr The source user space pointer.
 * @param len The length of the copy, in bytes.
 * @return 0 if successful, negative error codes if error'd.
 *         At the time of writing, the only possible error return is -EFAULT.
 */
ssize_t copy_from_user(void *data, const void *user, size_t size)
{
    DO_USER_POINTER_CHECKS(user, size);
    return copy_from_user_internal(data, user, size);
}

/**
 * @brief Memsets user space memory.
 *
 * @param data The destionation user space pointer.
 * @param data The destionation kernel pointer.
 * @param len The length of the copy, in bytes.
 * @return 0 if successful, negative error codes if error'd.
 *         At the time of writing, the only possible error return is -EFAULT.
 */
ssize_t user_memset(void *data, int val, size_t len)
{
    DO_USER_POINTER_CHECKS(data, len);
    return user_memset_internal(data, val, len);
}

ssize_t strlen_user(const char *user)
{
    DO_USER_POINTER_CHECK_NO_SIZE(user);
    return strlen_user_internal(user);
}

#define ALLOW_USER_MEMORY_ACCESS
#define CLEAR_USER_MEMORY_ACCESS

long get_user32(unsigned int *uaddr, unsigned int *dest)
{
    // Note: GCC doesn't allow output constraints in inline assembly
    // Because of this, we add dest as an input constraint and clobber memory
    // It's not ideal, but that's the way we need to do things, unfortunately.
    DO_USER_POINTER_CHECKS(uaddr, sizeof(uint32_t));
    ALLOW_USER_MEMORY_ACCESS;
    __asm__ goto("%=: ldr w3, [%1]\n\t"
                 "    str w3, %0\n\t"
                 ".pushsection .ehtable\n\t"
                 ".dword %=b\n\t"
                 ".dword %l2\n\t"
                 ".popsection\n\t" ::"m"(*dest),
                 "r"(uaddr)
                 : "memory", "x3"
                 : fault);
    CLEAR_USER_MEMORY_ACCESS;
    return 0;
fault:
    CLEAR_USER_MEMORY_ACCESS;
    return -EFAULT;
}

long get_user64(unsigned long *uaddr, unsigned long *dest)
{
    DO_USER_POINTER_CHECKS(uaddr, sizeof(uint64_t));
    ALLOW_USER_MEMORY_ACCESS;
    __asm__ goto("%=: ldr x3, [%1]\n\t"
                 "    str x3, %0\n\t"
                 ".pushsection .ehtable\n\t"
                 ".dword %=b\n\t"
                 ".dword %l2\n\t"
                 ".popsection\n\t" ::"m"(*dest),
                 "r"(uaddr)
                 : "memory", "x3"
                 : fault);
    CLEAR_USER_MEMORY_ACCESS;
    return 0;
fault:
    CLEAR_USER_MEMORY_ACCESS;
    return -EFAULT;
}
