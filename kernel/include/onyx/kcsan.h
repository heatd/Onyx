/* SPDX-License-Identifier: GPL-2.0 */
/*
 * The Kernel Concurrency Sanitizer (KCSAN) infrastructure. Public interface and
 * data structures to set up runtime. See kcsan-checks.h for explicit checks and
 * modifiers. For more info please see Documentation/dev-tools/kcsan.rst.
 *
 * Copyright (C) 2019, Google LLC.
 */

#ifndef _ONYX_KCSAN_H
#define _ONYX_KCSAN_H

#include <onyx/list.h>
#include <onyx/types.h>

/* Access types -- if KCSAN_ACCESS_WRITE is not set, the access is a read. */
#define KCSAN_ACCESS_WRITE    (1 << 0) /* Access is a write. */
#define KCSAN_ACCESS_COMPOUND (1 << 1) /* Compounded read-write instrumentation. */
#define KCSAN_ACCESS_ATOMIC   (1 << 2) /* Access is atomic. */
/* The following are special, and never due to compiler instrumentation. */
#define KCSAN_ACCESS_ASSERT   (1 << 3) /* Access is an assertion. */
#define KCSAN_ACCESS_SCOPED   (1 << 4) /* Access is a scoped access. */

/*
 * __kcsan_*: Always calls into the runtime when KCSAN is enabled. This may be used
 * even in compilation units that selectively disable KCSAN, but must use KCSAN
 * to validate access to an address. Never use these in header files!
 */

/**
 * __kcsan_check_access - check generic access for races
 *
 * @ptr: address of access
 * @size: size of access
 * @type: access type modifier
 */
void __kcsan_check_access(const volatile void *ptr, size_t size, int type);

/*
 * See definition of __tsan_atomic_signal_fence() in kernel/kcsan/core.c.
 * Note: The mappings are arbitrary, and do not reflect any real mappings of C11
 * memory orders to the LKMM memory orders and vice-versa!
 */
#define __KCSAN_BARRIER_TO_SIGNAL_FENCE_mb      __ATOMIC_SEQ_CST
#define __KCSAN_BARRIER_TO_SIGNAL_FENCE_wmb     __ATOMIC_ACQ_REL
#define __KCSAN_BARRIER_TO_SIGNAL_FENCE_rmb     __ATOMIC_ACQUIRE
#define __KCSAN_BARRIER_TO_SIGNAL_FENCE_release __ATOMIC_RELEASE

struct kcsan_scoped_access
{
    union {
        struct list_head list; /* scoped_accesses list */
        /*
         * Not an entry in scoped_accesses list; stack depth from where
         * the access was initialized.
         */
        int stack_depth;
    };

    /* Access information. */
    const volatile void *ptr;
    size_t size;
    int type;
    /* Location where scoped access was set up. */
    unsigned long ip;
};

struct kcsan_ctx
{
    int disable_count;  /* disable counter */
    int disable_scoped; /* disable scoped access counter */
    int atomic_next;    /* number of following atomic ops */

    /*
     * We distinguish between: (a) nestable atomic regions that may contain
     * other nestable regions; and (b) flat atomic regions that do not keep
     * track of nesting. Both (a) and (b) are entirely independent of each
     * other, and a flat region may be started in a nestable region or
     * vice-versa.
     *
     * This is required because, for example, in the annotations for
     * seqlocks, we declare seqlock writer critical sections as (a) nestable
     * atomic regions, but reader critical sections as (b) flat atomic
     * regions, but have encountered cases where seqlock reader critical
     * sections are contained within writer critical sections (the opposite
     * may be possible, too).
     *
     * To support these cases, we independently track the depth of nesting
     * for (a), and whether the leaf level is flat for (b).
     */
    int atomic_nest_count;
    bool in_flat_atomic;

    /*
     * Access mask for all accesses if non-zero.
     */
    unsigned long access_mask;

    /* List of scoped accesses; likely to be empty. */
    struct list_head scoped_accesses;
#define CONFIG_KCSAN_WEAK_MEMORY 1
#ifdef CONFIG_KCSAN_WEAK_MEMORY
    /*
     * Scoped access for modeling access reordering to detect missing memory
     * barriers; only keep 1 to keep fast-path complexity manageable.
     */
    struct kcsan_scoped_access reorder_access;
#endif
};

#endif
