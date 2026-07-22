/*
 * Copyright (c) 2026 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <string.h>

#include <onyx/arm64/mmu.h>
#include <onyx/compiler.h>
#include <onyx/cpu.h>
#include <onyx/init.h>
#include <onyx/page.h>
#include <onyx/percpu.h>
#include <onyx/pgtable.h>
#include <onyx/smp.h>
#include <onyx/spinlock.h>
#include <onyx/vm.h>

#include <linux/lockdep.h>

#define NR_ASIDS 0x10000

/* Reserve ASID 0 for kernel purposes + as a simple sentinel value */
#define NO_ASID 0

#define NR_ASID_WORDS NR_ASIDS / BITS_PER_LONG

static DEFINE_SPINLOCK(asid_lock);
static unsigned long asid_bitmap[NR_ASID_WORDS];
static unsigned int max_asids = NR_ASIDS;
static unsigned long asid_generation = ASID_GEN_INCREMENT;

PER_CPU_VAR(u64 active_context) = NO_ASID;
PER_CPU_VAR(struct arch_mm_address_space *loaded_mm) = NULL;

static void set_asid_used(u16 asid)
{
    asid_bitmap[asid / BITS_PER_LONG] |= (1UL << (asid % BITS_PER_LONG));
}

static void set_asid_free(u16 asid)
{
    asid_bitmap[asid / BITS_PER_LONG] &= ~(1UL << (asid % BITS_PER_LONG));
}

/**
 * @brief Finds a free ASID
 *
 * @return The ASID, or NO_ASID if none is available
 */
static int find_free_asid(void)
{
    unsigned long i, word;
    int bit;

    lockdep_assert_held(&asid_lock);
    for (i = 0; i < NR_ASID_WORDS; i++)
    {
        word = asid_bitmap[i];
        if (~word == 0)
            continue;
        bit = __builtin_ffsl(~word) - 1;
        asid_bitmap[i] |= (1UL << bit);
        return (i * BITS_PER_LONG) + bit;
    }

    return NO_ASID;
}

/**
 * @brief Invalidates all ASIDs that aren't being used.
 *
 */
static void asid_rollover(void)
{
    u64 *other, other_ctx;
    unsigned int cpu;
    int active_asid;

    /* We need the asid lock to protect against other CPUs trying to allocate ASIDs while we're
     * doing this */
    lockdep_assert_held(&asid_lock);

    __atomic_add_fetch(&asid_generation, ASID_GEN_INCREMENT, __ATOMIC_RELAXED);

    memset(asid_bitmap, 0, NR_ASID_WORDS * sizeof(unsigned long));
    set_asid_used(NO_ASID);
    /* Grab active CPUs's ASIDs and save them. */
    for (cpu = 0; cpu < get_nr_cpus(); cpu++)
    {
        /* Grab the active ASID and reserve it. The cmpxchg ensures that we don't race with an MM
         * switch. */
        other = other_cpu_get_ptr(active_context, cpu);
        other_ctx = READ_ONCE(*other);

    retry:
        active_asid = ctx2asid(other_ctx);
        /* no asid? ignore. */
        if (active_asid != NO_ASID)
            set_asid_used(active_asid);
        if (!__atomic_compare_exchange_n(other, &other_ctx, asid2ctx(active_asid, asid_generation),
                                         false, __ATOMIC_RELEASE, __ATOMIC_RELAXED))
        {
            /* We raced with an MM switch. Try again. */
            set_asid_free(active_asid);
            goto retry;
        }
    }
}

void asid_allocate(struct arch_mm_address_space *mm, bool set)
{
    int asid;

    spin_lock(&asid_lock);

    /* Somebody may have grabbed a valid ASID while we were waiting for the lock. */
    if (ctx2gen(mm->context_id) == asid_generation)
    {
        asid = ctx2asid(mm->context_id);
        goto out;
    }

    asid = find_free_asid();
    if (unlikely(asid == NO_ASID))
    {
        asid_rollover();
        asid = find_free_asid();
        CHECK(asid != NO_ASID);
    }

    mm->context_id = asid2ctx(asid, asid_generation);
    set_asid_used(asid);

out:
    if (set)
        write_per_cpu(active_context, mm->context_id);
    flush_tlb_asid(asid);
    spin_unlock(&asid_lock);
}

void arm64_switch_mm(struct arch_mm_address_space *to)
{
    struct arch_mm_address_space *from;
    u64 old_ctx_id;
    u64 next_ctx_id = READ_ONCE(asid_generation) | NO_ASID;
    /* It is guaranteed that the current ASID is valid. This cannot be swept from under us. */

    /* Sidestep any weird logic if this is a kernel address space. */
    if (to == &kernel_address_space.arch_mmu)
        return;
    from = get_per_cpu(loaded_mm);
    /* nothing to do if we're switching to the same address space. */
    if (from == to)
        return;

    if (likely(to))
        next_ctx_id = to->context_id;

    /* Swap ASIDs. External observers (asid rollover) will observe the new context id. */
    old_ctx_id =
        __atomic_exchange_n(get_per_cpu_ptr(active_context), next_ctx_id, __ATOMIC_RELAXED);

    if (likely(to) && ctx2gen(old_ctx_id) != ctx2gen(next_ctx_id))
    {
        /* We rolled over. The current ASID is invalid. Allocate a new one. This is safe against
         * races, since it takes the asid lock. */
        asid_allocate(to, true);
    }

    if (likely(from))
        from->context_id = old_ctx_id;

    if (to)
        paging_load_el0((unsigned long) to->top_pt, ctx2asid(to->context_id));
    write_per_cpu(loaded_mm, to);
}

void arm64_free_asid(struct arch_mm_address_space *mm)
{
    spin_lock(&asid_lock);

    if (ctx2gen(mm->context_id) == asid_generation)
        set_asid_free(ctx2asid(mm->context_id));

    spin_unlock(&asid_lock);
}

static void arm64_asid_init(void)
{
    (void) max_asids;
    set_asid_used(NO_ASID);
}
INIT_LEVEL_VERY_EARLY_PLATFORM_ENTRY(arm64_asid_init);
