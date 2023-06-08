/*
 * Copyright (c) 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef _ONYX_KTSAN_PUBLIC_H
#define _ONYX_KTSAN_PUBLIC_H

#include <onyx/types.h>

struct thread;
struct page;

#ifdef CONFIG_KTSAN
int kt_create_thread(struct thread *);
void kt_free_thread(struct thread *);
int kt_alloc_pages(struct page *page, size_t nr);
void kt_free_pages(struct page *page, size_t nr);
void kt_mutex_post_lock(void *ptr);
void kt_mutex_pre_release(void *ptr);
#else
static inline int kt_create_thread(struct thread *)
{
    return 0;
}

static inline void kt_free_thread(struct thread *)
{
}

static inline int kt_alloc_pages(struct page *page, size_t nr)
{
    return 0;
}

static inline void kt_free_pages(struct page *page, size_t nr)
{
}

static inline void kt_mutex_post_lock(void *ptr)
{
}

static inline void kt_mutex_pre_release(void *ptr)
{
}

#endif

#endif
