/*
 * Copyright (c) 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include <onyx/fnv.h>
#include <onyx/mm/slab.h>
#include <onyx/page.h>
#include <onyx/spinlock.h>
#include <onyx/stackdepot.h>
#include <onyx/types.h>
#include <onyx/vm.h>

/* Lets use a similar design to llvm's sanitizer_common_stackdepot and linux's lib/stackdepot.c.
 * We have capacity for N slabs of 4 pages each. We manually allocate stacks in slabs and link them
 * in a hash table. To find a specific trace, we index into the hash table using the hash of the
 * stack trace. To allocate a new stack trace, we first look for it, then if we can't find it we
 * simply allocate a new one on a slab and link that.
 */

// Use order-2 pages for each stackdepot slab
#define STACKDEPOT_SLAB_ORDER  (2)
#define STACKDEPOT_SLAB_SIZE   (PAGE_SIZE << STACKDEPOT_SLAB_ORDER)
#define STACKDEPOT_OFFSET_MASK (STACKDEPOT_SLAB_SIZE - 1)
#define STACKDEPOT_OFFSET_BITS (PAGE_SHIFT + STACKDEPOT_SLAB_ORDER)

#define STACKDEPOT_MAX_SLABS 2048
#define STACKDEPOT_SLAB_BITS 11

#define STACKDEPOT_HASHTABLE_ORDER (16)
#define STACKDEPOT_HASHTABLE_SIZE  (1u << STACKDEPOT_HASHTABLE_ORDER)
#define STACKDEPOT_HASHTABLE_MASK  (STACKDEPOT_HASHTABLE_SIZE - 1)

union handle_details {
    depot_stack_handle_t handle;
    struct
    {
        u32 valid : 1;
        u32 slab : STACKDEPOT_SLAB_BITS;
        u32 offset : STACKDEPOT_OFFSET_BITS;
    };
};

static struct stacktrace *depot_stacks[STACKDEPOT_HASHTABLE_SIZE];
static spinlock depot_locks[STACKDEPOT_HASHTABLE_SIZE];

/**
 * @brief Find a stack in the hashtable
 * Note: This function can run locklessly (since we can't remove) as well as with locks.
 *
 * @param entries Pointer to stack trace
 * @param nr_entries Number of entries
 * @param hash Hash of stack trace
 * @return struct stacktrace* if found, else null
 */
static struct stacktrace *__findstack(unsigned long *entries, unsigned long nr_entries, u32 hash)
{
    u32 index = hash & STACKDEPOT_HASHTABLE_MASK;

    for (stacktrace *s = depot_stacks[index]; s; s = s->next)
    {
        if (s->hash != hash)
            continue;
        if (s->size != nr_entries)
            continue;
        if (!memcmp(s->entries, entries, nr_entries * sizeof(unsigned long)))
            return s;
    }

    return nullptr;
}

static u8 *slabs[STACKDEPOT_MAX_SLABS];
static u32 curr_slab = -1;
static u32 slab_off = STACKDEPOT_SLAB_SIZE;
static spinlock slabs_lock;

struct stacktrace *stackdepot_from_handle(depot_stack_handle_t handle)
{
    union handle_details details = {.handle = handle};
    DCHECK(details.valid);

    u8 *slab = slabs[details.slab];
    DCHECK(slab != nullptr);

    return (struct stacktrace *) (slab + details.offset);
}

static depot_stack_handle_t stackdepot_trace_to_handle(struct stacktrace *trace, u32 slab_idx)
{
    // All slabs are STACKDEPOT_SLAB_SIZE aligned, so use size - 1 as a mask for the offset
    unsigned long p = (unsigned long) trace;
    u32 offset = p & (STACKDEPOT_SLAB_SIZE - 1);

    return handle_details{.valid = 1, .slab = slab_idx, .offset = offset}.handle;
}

static struct stacktrace *stackdepot_alloc_stack(unsigned long *entries, unsigned long nr_entries,
                                                 u32 hash)
{
    scoped_lock<spinlock, true> g{slabs_lock};
    size_t trace_size = sizeof(struct stacktrace) + nr_entries * sizeof(unsigned long);

    // Bad trace which we will not be able to store, return
    // TODO: printk/printf log? but we're under nohardirq :(
    if (trace_size > STACKDEPOT_SLAB_SIZE)
        return nullptr;

    if (STACKDEPOT_SLAB_SIZE - slab_off < trace_size)
    {
        // Ditch this slab, allocate a new one

        if (curr_slab + 1 == STACKDEPOT_MAX_SLABS)
            return nullptr;
        struct page *slab = alloc_pages(STACKDEPOT_SLAB_ORDER, GFP_KERNEL | __GFP_NO_INSTRUMENT);
        if (!slab)
            return nullptr;
        curr_slab++;
        slab_off = 0;
        slabs[curr_slab] = (u8 *) PAGE_TO_VIRT(slab);
    }

    struct stacktrace *s = (struct stacktrace *) (slabs[curr_slab] + slab_off);
    s->hash = hash;
    s->size = nr_entries;
    memcpy(s->entries, entries, s->size * sizeof(unsigned long));
    s->handle = stackdepot_trace_to_handle(s, curr_slab);

    slab_off += trace_size;

    u32 bucket = hash & STACKDEPOT_HASHTABLE_MASK;
    s->next = depot_stacks[bucket];
    depot_stacks[bucket] = s;

    return s;
}

static size_t depot_found = 0;
static size_t depot_alloc = 0;

depot_stack_handle_t stackdepot_save_stack(unsigned long *entries, unsigned long nr_entries)
{
    fnv_hash_t hash = fnv_hash(entries, nr_entries * sizeof(unsigned long));
    struct stacktrace *s = __findstack(entries, nr_entries, hash);

    if (!s) [[unlikely]]
    {
        scoped_lock<spinlock, true> g{depot_locks[hash & STACKDEPOT_HASHTABLE_MASK]};

        s = __findstack(entries, nr_entries, hash);
        if (!s)
        {
            s = stackdepot_alloc_stack(entries, nr_entries, hash);
            if (!s)
                return DEPOT_STACK_HANDLE_INVALID;
        }

        depot_alloc++;
    }
    else
        depot_found++;

    return s->handle;
}
