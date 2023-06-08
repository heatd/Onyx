/*
 * Copyright (c) 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#include <onyx/irq.h>
#include <onyx/thread.h>
#include <onyx/types.h>

#include "ktsan.h"

// TODO: TSAN v3 allegedly has a different algorithm that only increments on mutex unlocks, RELEASE
// atomics, barriers, etc and as such is 2x more space efficient. Investigate.

static void print_shadow_word(kt_shadow word)
{
    printk("Clock %lu, tid %u, write %s, atomic %s, offset %u, size %u\n",
           (unsigned long) word.clock, word.tid, word.write ? "true" : "false",
           word.atomic ? "true" : "false", word.offset, 1 << word.size);
}

// XXX HACK
char *resolve_sym(void *address);

static void kt_report_race(kt_shadow old, kt_shadow new_val, kt_thread *thr, unsigned long addr)
{
    // TODO: Proper report
    thr->nr_races++;
    print_shadow_word(old);
    print_shadow_word(new_val);

    // Prevent further trapping on this address by storing zero-entries in this word's shadow
    kt_clear_shadow_one(addr);

    if (thr->flags & KT_FLAG_NO_REPORT)
        return;
    kt_stack stack;
    kt_event_log_replay_stack(thr->log, new_val.clock, KT_EVENT_ACCESS,
                              kt_compress_ptr((void *) addr), &stack);

    for (u32 i = 0; i < stack.size; i++)
    {
        auto sym = resolve_sym((void *) stack.pcs[i]);
        printk("stack frame #%u: %s\n", i, sym);
        free(sym);
    }

    printk("Their clock, to us: %lu\n", kt_clk_get(&thr->clk, old.tid));

    auto old_thread = kt_get_thread(old.tid);

    if (old_thread)
    {
        kt_event_log_replay_stack(old_thread->log, old.clock, KT_EVENT_ACCESS,
                                  kt_compress_ptr((void *) addr), &stack);

        for (u32 i = 0; i < stack.size; i++)
        {
            auto sym = resolve_sym((void *) stack.pcs[i]);
            printk("stack frame #%u: %s\n", i, sym);
            free(sym);
        }

        printk("old_thread: %p\n", old_thread);
    }

    panic("race on %p", addr);
}

enum class update_result
{
    none = 0,
    stored,
    race
};

static update_result update_one_shadow_state(kt_shadow *shadow, kt_shadow new_val, bool stored,
                                             kt_thread *thr, unsigned long addr)
{
    kt_shadow load;
    load.word = __atomic_load_n(&shadow->word, __ATOMIC_ACQUIRE);
    if (load.word == 0)
    {
        // Yay, vacant!
        if (!stored)
        {
            __atomic_store_n(&shadow->word, new_val.word, __ATOMIC_RELEASE);
            return update_result::stored;
        }

        return update_result::none;
    }

    if (load.offset == new_val.offset ||
        check_for_overlap(load.offset, load.offset + (1UL << load.size), new_val.offset,
                          new_val.offset + (1UL << new_val.size)))
    {
        if (load.tid == new_val.tid)
            return update_result::none;

        /* Check for happens-before */
        if (kt_clk_get(&thr->clk, load.tid) >= load.clock)
        {
            if (!stored)
                __atomic_store_n(&shadow->word, new_val.word, __ATOMIC_RELEASE);
            return update_result::stored;
        }

        // If no write is involved, it's not a race
        if (!load.write && !new_val.write)
            return update_result::none;
        // If the two writes are atomic, this is ok
        if (load.atomic && new_val.atomic)
            return update_result::none;

        kt_report_race(load, new_val, thr, addr);
        return update_result::race;
    }

    return update_result::none;
}

void kt_access(void *ptr, u16 size, bool write)
{
    auto kt = ktsan_enter();
    if (!kt)
        return;

    kt_event_log_write(kt, KT_EVENT_ACCESS, kt_compress_ptr(ptr));

    kt_shadow word;
    word.clock = kt_clk_get(&kt->clk, kt->id);
    word.offset = (unsigned long) ptr & 7;
    word.size = ilog2(size);
    word.tid = kt->id;
    word.write = write;

    auto shadow = kt_get_shadow(ptr);
    if (!shadow)
    {
        ktsan_exit(kt);
        return;
    }

    bool stored = false;

    for (unsigned long i = 0; i < KTSAN_SHADOW_SLOTS; i++)
    {
        const auto result =
            update_one_shadow_state(shadow + i, word, stored, kt, (unsigned long) ptr);

        // Do not go through more shadow slots if we've raced already
        if (result == update_result::race)
        {
            // Pretend we've stored, let's not store this access though
            stored = true;
            break;
        }
        // This works branchlessly because update_result::stored = 1
        stored |= (int) result;
    }

    if (!stored)
    {
        // If we weren't able to store it yet, pick a random slot
        __atomic_store_n(&(shadow + (word.clock % KTSAN_SHADOW_SLOTS))->word, word.word,
                         __ATOMIC_RELEASE);
    }

    ktsan_exit(kt);
}

#define TSAN_ACCESSOR_read  false
#define TSAN_ACCESSOR_write true

#define TSAN_SIMPLE_RW_ACCESSOR(size, access)         \
    void __tsan_##access##size(void *ptr)             \
    {                                                 \
        kt_access(ptr, size, TSAN_ACCESSOR_##access); \
    }

extern "C"
{
TSAN_SIMPLE_RW_ACCESSOR(1, read);
TSAN_SIMPLE_RW_ACCESSOR(2, read);
TSAN_SIMPLE_RW_ACCESSOR(4, read);
TSAN_SIMPLE_RW_ACCESSOR(8, read);
TSAN_SIMPLE_RW_ACCESSOR(16, read);

TSAN_SIMPLE_RW_ACCESSOR(1, write);
TSAN_SIMPLE_RW_ACCESSOR(2, write);
TSAN_SIMPLE_RW_ACCESSOR(4, write);
TSAN_SIMPLE_RW_ACCESSOR(8, write);
TSAN_SIMPLE_RW_ACCESSOR(16, write);

void __tsan_func_entry(void *callpc)
{
    auto kt = ktsan_enter();
    if (!kt)
        return;

    kt_event_log_write(kt, KT_EVENT_FUNC_ENTRY, kt_compress_ptr(callpc));

    ktsan_exit(kt);
}

void __tsan_func_exit()
{
    auto kt = ktsan_enter();
    if (!kt)
        return;

    kt_event_log_write(kt, KT_EVENT_FUNC_EXIT, 0);

    ktsan_exit(kt);
}

void __tsan_vptr_update(void **pvptr, void *new_val)
{
}

void __tsan_read_range(void *addr, unsigned long size)
{
}

void __tsan_write_range(void *addr, unsigned long size)
{
}

#define __KTSAN_ATOMIC_ADDR_VAL(size, operation, atomic_suff)                      \
    u##size __tsan_atomic##size##_##operation(void *addr, u##size val,             \
                                              ktsan_memory_order memorder)         \
    {                                                                              \
        /* TODO: Make this work properly */                                        \
        return __atomic_##operation##atomic_suff((u##size *) addr, val, memorder); \
    }

#define KTSAN_ATOMIC_ADDR_VAL(size, operation) __KTSAN_ATOMIC_ADDR_VAL(size, operation, )

KTSAN_ATOMIC_ADDR_VAL(8, fetch_or);
KTSAN_ATOMIC_ADDR_VAL(16, fetch_or);
KTSAN_ATOMIC_ADDR_VAL(32, fetch_or);
KTSAN_ATOMIC_ADDR_VAL(64, fetch_or);

KTSAN_ATOMIC_ADDR_VAL(8, fetch_and);
KTSAN_ATOMIC_ADDR_VAL(16, fetch_and);
KTSAN_ATOMIC_ADDR_VAL(32, fetch_and);
KTSAN_ATOMIC_ADDR_VAL(64, fetch_and);

KTSAN_ATOMIC_ADDR_VAL(8, fetch_add);
KTSAN_ATOMIC_ADDR_VAL(16, fetch_add);
KTSAN_ATOMIC_ADDR_VAL(32, fetch_add);
KTSAN_ATOMIC_ADDR_VAL(64, fetch_add);

KTSAN_ATOMIC_ADDR_VAL(8, fetch_sub);
KTSAN_ATOMIC_ADDR_VAL(16, fetch_sub);
KTSAN_ATOMIC_ADDR_VAL(32, fetch_sub);
KTSAN_ATOMIC_ADDR_VAL(64, fetch_sub);

#define KTSAN_ATOMIC_STORE(size)                                                           \
    void __tsan_atomic##size##_store(void *addr, u##size val, ktsan_memory_order memorder) \
    {                                                                                      \
        /* TODO: Make this work properly */                                                \
        __atomic_store_n((u##size *) addr, val, memorder);                                 \
    }

KTSAN_ATOMIC_STORE(8);
KTSAN_ATOMIC_STORE(16);
KTSAN_ATOMIC_STORE(32);
KTSAN_ATOMIC_STORE(64);

#define __KTSAN_ATOMIC_ADDR_NO_OP(size, operation, atomic_suff)                        \
    u##size __tsan_atomic##size##_##operation(void *addr, ktsan_memory_order memorder) \
    {                                                                                  \
        /* TODO: Make this work properly */                                            \
        return __atomic_##operation##atomic_suff((u##size *) addr, memorder);          \
    }

__KTSAN_ATOMIC_ADDR_NO_OP(8, load, _n);
__KTSAN_ATOMIC_ADDR_NO_OP(16, load, _n);
__KTSAN_ATOMIC_ADDR_NO_OP(32, load, _n);
__KTSAN_ATOMIC_ADDR_NO_OP(64, load, _n);

__KTSAN_ATOMIC_ADDR_VAL(8, exchange, _n);
__KTSAN_ATOMIC_ADDR_VAL(16, exchange, _n);
__KTSAN_ATOMIC_ADDR_VAL(32, exchange, _n);
__KTSAN_ATOMIC_ADDR_VAL(64, exchange, _n);

#define atomic_cmpxchg_arg_weak   true
#define atomic_cmpxchg_arg_strong false
#define KTSAN_CMPXCHG(size, variant)                                                               \
    int __tsan_atomic##size##_compare_exchange_##variant(void *addr, u##size *expected,            \
                                                         u##size val, ktsan_memory_order memorder, \
                                                         ktsan_memory_order failmem)               \
    {                                                                                              \
        /* TODO: Make this work properly */                                                        \
        return __atomic_compare_exchange_n((u##size *) addr, expected, val,                        \
                                           atomic_cmpxchg_arg_##variant, memorder, failmem);       \
    }

KTSAN_CMPXCHG(8, weak);
KTSAN_CMPXCHG(16, weak);
KTSAN_CMPXCHG(32, weak);
KTSAN_CMPXCHG(64, weak);

KTSAN_CMPXCHG(8, strong);
KTSAN_CMPXCHG(16, strong);
KTSAN_CMPXCHG(32, strong);
KTSAN_CMPXCHG(64, strong);

void __tsan_atomic_thread_fence(ktsan_memory_order memorder)
{
}
}
