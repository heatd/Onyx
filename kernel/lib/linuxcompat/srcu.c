/*
 * Copyright (c) 2025 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <linux/srcu.h>

int init_srcu_struct(struct srcu_struct *srcu)
{
    mutex_init(&srcu->lock);
    srcu->completed = 0;
    srcu->ongoing[0] = 0;
    srcu->ongoing[1] = 0;
    return 0;
}

int srcu_read_lock(struct srcu_struct *srcu)
{
    unsigned int idx;

    /* Grab the current completed generation. We will add ourselves to that (bottom bit controls
     * exactly which). */
    idx = READ_ONCE(srcu->completed) & 1;

    /* pairs with synchronize_srcu() machinery */
    smp_mb();
    __atomic_add_fetch(&srcu->ongoing[idx], 1, __ATOMIC_RELAXED);
    return idx;
}

void srcu_read_unlock(struct srcu_struct *srcu, int idx)
{
    /* Avoid leaking the srcu section */
    smp_mb();
    __atomic_sub_fetch(&srcu->ongoing[idx], 1, __ATOMIC_RELAXED);
}

void synchronize_srcu(struct srcu_struct *srcu)
{
    WARN_ON_ONCE(1);
    /* TODO */
}
