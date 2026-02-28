/*
 * Copyright (c) 2025 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include <linux/atomic.h>
#include <linux/mutex.h>

int atomic_dec_and_mutex_lock(atomic_t *v, struct mutex *lock)
{
    if (atomic_add_unless(v, -1, 1))
        return 0;

    mutex_lock(lock);
    if (!atomic_dec_and_test(v))
    {
        /* Did not hit 0, unlock and return false */
        mutex_unlock(lock);
        return 0;
    }
    return 1;
}
