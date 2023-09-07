/*
 * Copyright (c) 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef _ONYX_STATIC_KEY_H
#define _ONYX_STATIC_KEY_H

#include <platform/jump_label.h>

struct static_key
{
    unsigned long val;
};

#define DEFINE_STATIC_KEY_TRUE(name)  struct static_key name = {.val = 1}
#define DEFINE_STATIC_KEY_FALSE(name) struct static_key name = {.val = 0}

#if !ARCH_HAS_JUMP_LABEL

#define static_branch_likely(key)     \
    ({                                \
        bool __ret = true;            \
        if (!(key)->val) [[unlikely]] \
            __ret = false;            \
        __ret;                        \
    })

#define static_branch_unlikely(key)  \
    ({                               \
        bool __ret = false;          \
        if ((key)->val) [[unlikely]] \
            __ret = true;            \
        __ret;                       \
    })

static inline void __STATIC_BRANCH_ENABLE(struct static_key *k)
{
}

static inline void __STATIC_BRANCH_DISABLE(struct static_key *k)
{
}

#else

#define static_branch_likely(key)   jump_label_branch<true>(key)
#define static_branch_unlikely(key) jump_label_branch<false>(key)

#define __STATIC_BRANCH_ENABLE(key)  jump_label_patch_branch(key, true)
#define __STATIC_BRANCH_DISABLE(key) jump_label_patch_branch(key, false)

#endif

__always_inline void static_branch_enable(struct static_key *key)
{
    unsigned long old = __atomic_exchange_n(&key->val, 1, __ATOMIC_RELEASE);

    if (old == 0)
        __STATIC_BRANCH_ENABLE(key);
}

__always_inline void static_branch_disable(struct static_key *key)
{
    unsigned long old = __atomic_exchange_n(&key->val, 0, __ATOMIC_RELEASE);

    if (old > 0)
        __STATIC_BRANCH_DISABLE(key);
}

__always_inline void static_branch_inc(struct static_key *key)
{
    /* We can use add_fetch and sub_fetch here since we're incrementing. We can skip the cmpxchg
     * loop then, and have a good performance improvement.
     */
    if (__atomic_add_fetch(&key->val, 1, __ATOMIC_RELEASE) == 1)
        __STATIC_BRANCH_ENABLE(key);
}

__always_inline void static_branch_dec(struct static_key *key)
{
    if (__atomic_sub_fetch(&key->val, 1, __ATOMIC_RELEASE) == 0)
        __STATIC_BRANCH_DISABLE(key);
}

__always_inline bool static_branch_is_enabled(struct static_key *key)
{
    return __atomic_load_n(&key->val, __ATOMIC_RELAXED) > 0;
}

#endif
