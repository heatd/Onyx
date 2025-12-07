#ifndef _LINUX_HIGHMEM_H
#define _LINUX_HIGHMEM_H

#include <onyx/scheduler.h>
#include <linux/mm.h>
#include <linux/kernel.h>

static inline void *kmap_atomic(struct page *page)
{
    pagefault_disable();
    return page_address(page);
}

static inline void kunmap_atomic(void *addr)
{
    pagefault_enable();
}

#endif
