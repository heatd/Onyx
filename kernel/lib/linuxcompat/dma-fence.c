/*
 * Copyright (c) 2026 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include <linux/dma-fence.h>

void dma_fence_release(struct kref *kref)
{
    WARN_ON_ONCE(1);
}
