/*
 * Copyright (c) 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef _ONYX_KCOV_H
#define _ONYX_KCOV_H

struct thread;

#ifdef CONFIG_KCOV

void kcov_free_thread(struct thread *thread);

#else

static inline void kcov_free_thread(struct thread *thread)
{
}

#endif

#endif
