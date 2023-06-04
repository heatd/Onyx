/*
 * Copyright (c) 2017 - 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>

#include <onyx/bootmem.h>
#include <onyx/fnv.h>
#include <onyx/log.h>
#include <onyx/page.h>
#include <onyx/vm.h>
#include <onyx/wait_queue.h>

#include <onyx/hashtable.hpp>

/* struct page array a-la linux kernel */
struct page *page_map = NULL;
static size_t num_pages = 0;
static unsigned long maxpfn = 0;
unsigned long base_pfn = 0;

struct page *page_add_page(void *paddr)
{
    struct page *page = phys_to_page((unsigned long) paddr);

    assert(page != NULL);
    memset(page, 0, sizeof(struct page));

    ++num_pages;

    return page;
}

void page_allocate_pagemap(unsigned long __maxpfn)
{
    maxpfn = __maxpfn;
    page_map = (page *) __ksbrk((maxpfn - base_pfn) * sizeof(struct page));
}

struct page *phys_to_page(uintptr_t phys)
{
    unsigned long pfn = phys >> PAGE_SHIFT;
    assert(pfn <= maxpfn);
    return page_map + pfn - base_pfn;
}

extern unsigned char kernel_start;
extern unsigned char kernel_end;
uint64_t kernel_phys_offset = 0;

/**
 * @brief Retrieves the kernel's limits in physical memory and virtual memory.
 *
 * @param l A pointer to a kernel_limits object where the limits will be placed.
 */
void get_kernel_limits(struct kernel_limits *l)
{
    uintptr_t start_virt = (uintptr_t) &kernel_start;
    uintptr_t end_virt = (uintptr_t) &kernel_end;

    l->start_virt = start_virt;
    l->end_virt = end_virt;

    l->start_phys = start_virt - KERNEL_VIRTUAL_BASE + kernel_phys_offset;
    l->end_phys = end_virt - KERNEL_VIRTUAL_BASE + kernel_phys_offset;
}

bool klimits_present = false;

bool check_kernel_limits(void *__page)
{
    static struct kernel_limits l;
    uintptr_t page = (uintptr_t) __page;

    if (!klimits_present)
    {
        klimits_present = true;
        get_kernel_limits(&l);
        printf("Kernel limits: %lx-%lx phys, %lx-%lx virt\n", l.start_phys, l.end_phys,
               l.start_virt, l.end_virt);
    }

    return page >= l.start_phys && page < l.end_phys;
}

void reclaim_pages(unsigned long start, unsigned long end)
{
    unsigned long page_start = (unsigned long) page_align_up((void *) start);

    end &= ~(PAGE_SIZE - 1);
    size_t nr_pages = (end - page_start) / PAGE_SIZE;
    for (size_t i = 0; i < nr_pages; i++)
    {
        struct page *p = page_add_page((void *) page_start);

        __reclaim_page(p);
        page_start += PAGE_SIZE;
    }
}

fnv_hash_t hash_wait(struct page *page)
{
    return fnv_hash(&page, sizeof(void *));
}

#define PAGE_WQ_SIZE 512
#define PAGE_WQ_MASK (PAGE_WQ_SIZE - 1)

static wait_queue wait_queues[PAGE_WQ_SIZE];

struct page_wait_info
{
    struct page *page;

    bool operator==(const page_wait_info &other) const
    {
        return other.page == page;
    }

    bool operator!=(const page_wait_info &other) const
    {
        return !(*this == other);
    }
};

static int do_lock_page_wake(struct wait_queue_token *token, void *wake_context)
{
    const struct page_wait_info *info = (struct page_wait_info *) wake_context;
    const struct page_wait_info *info2 = (struct page_wait_info *) token->context;

    if (*info != *info2)
    {
        // Not our page, don't wake
        return WQ_WAKE_DO_NOT_WAKE;
    }

    // TODO: Fix this
    // Let's try to get the lock from the waking thread. If we're able to do this,
    // there's no need to wake every waiter on this page, we can get away with waking this
    // one and none else.
    // if (!try_lock_page(info->page))
    //{
    // Don't wake em, we couldn't get the lock
    // return WQ_WAKE_DO_NOT_WAKE;
    //}

    return WQ_WAKE_WAKE_EXCLUSIVE;
}

int __lock_page(page *p, bool interruptible)
{
    int st = 0;
    const int state = interruptible ? THREAD_INTERRUPTIBLE : THREAD_UNINTERRUPTIBLE;
    const auto hash = fnv_hash(&p, sizeof(page *));
    const auto index = hash & PAGE_WQ_MASK;

    page_wait_info winfo;
    winfo.page = p;

    struct wait_queue *wq = &wait_queues[index];

    auto flags = spin_lock_irqsave(&wq->lock);

    wait_queue_token token;

    token.thread = get_current_thread();
    token.context = &winfo;
    token.flags = 0;
    token.signaled = false;
    token.wake = do_lock_page_wake;

    __wait_queue_add(wq, &token);

    set_current_state(state);
    while (!try_lock_page(p))
    {
        if (interruptible && signal_is_pending())
        {
            st = -EINTR;
            break;
        }

        page_set_waiters(p);

        spin_unlock_irqrestore(&wq->lock, flags);

        sched_yield();

        flags = spin_lock_irqsave(&wq->lock);

        __wait_queue_remove(wq, &token);

        set_current_state(state);
        // XXX: wait_queue_remove zeroes token.context. Why?
        token.context = &winfo;
        __wait_queue_add(wq, &token);
    }

    set_current_state(THREAD_RUNNABLE);
    __wait_queue_remove(wq, &token);

    // Conditionally clear LOCK_CONTENTION if the queue is clear.
    // Note that this is not quite precise when we have multiple pages on a single queue.
    // Hopefully this is not common due to the hashtable.
    if (__wait_queue_is_empty(wq))
        page_clear_waiters(p);

    spin_unlock_irqrestore(&wq->lock, flags);

    return st;
}

void __unlock_page(struct page *p)
{
    // unlock_page, slow path (PAGE_FLAG_WAITERS).
    // Lets figure out what wait queue everyone is on, and try to wake em up
    // TODO: There's a funny idea here: Implement lock handoff from us to a waiter.
    const auto hash = fnv_hash(&p, sizeof(page *));
    const auto index = hash & PAGE_WQ_MASK;

    page_wait_info winfo;
    winfo.page = p;

    struct wait_queue *wq = &wait_queues[index];

    auto flags = spin_lock_irqsave(&wq->lock);

    unsigned long waked = __wait_queue_wake(wq, 0, &winfo, ULONG_MAX);

    if (waked == 0)
    {
        // If we did not wake up anyone, clear WAITERS as it's spuriously set.
        // Other setters will be under the queue lock as well, so there's no race here.
        // Note for future me: If we ever want to wait for arbitrary bits, this logic doesn't work.
        page_clear_waiters(p);
    }

    spin_unlock_irqrestore(&wq->lock, flags);
}
