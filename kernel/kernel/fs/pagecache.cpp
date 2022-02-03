/*
 * Copyright (c) 2017 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#include <onyx/compiler.h>
#include <onyx/condvar.h>
#include <onyx/cpu.h>
#include <onyx/dev.h>
#include <onyx/init.h>
#include <onyx/mm/flush.h>
#include <onyx/mutex.h>
#include <onyx/pagecache.h>
#include <onyx/panic.h>
#include <onyx/task_switching.h>
#include <onyx/utils.h>
#include <onyx/vm.h>

#include <onyx/atomic.hpp>

static atomic<size_t> used_cache_pages = 0;

#ifdef CONFIG_CHECK_PAGE_CACHE_INTEGRITY
uint32_t crc32_calculate(uint8_t *ptr, size_t len);
#endif

#define cache_block_from_fo(fo) container_of(fo, struct page_cache_block, fobj)

bool pagecache_is_dirty(struct flush_object *fo)
{
    struct page_cache_block *b = cache_block_from_fo(fo);

    return b->page->flags & PAGE_FLAG_DIRTY;
}

void wait_for_flush(struct page *page)
{
    /* TODO: busy sleeping is bad. Add a wait queue? */
    while (page->flags & PAGE_FLAG_FLUSHING)
        cpu_relax();
}

void pagecache_set_dirty(bool dirty, struct flush_object *fo)
{
    struct page_cache_block *b = cache_block_from_fo(fo);
    struct page *page = b->page;

    if (dirty)
    {
        wait_for_flush(page);
        __sync_fetch_and_or(&page->flags, PAGE_FLAG_DIRTY);
    }
    else
    {
        /* Re-write-protect shared mappings */
        struct vm_object *vmo = b->node->i_pages;
        vm_wp_page_for_every_region(page, b->offset, vmo);

        __sync_fetch_and_and(&page->flags, ~(PAGE_FLAG_DIRTY | PAGE_FLAG_FLUSHING));
    }
}

ssize_t pagecache_flush(struct flush_object *fo)
{
    struct page_cache_block *b = cache_block_from_fo(fo);
    struct page *page = b->page;

    __sync_or_and_fetch(&page->flags, PAGE_FLAG_FLUSHING);

    assert(b->node->i_fops->writepage != NULL);
    return b->node->i_fops->writepage(b->page, b->offset, b->node);
}

const struct flush_ops pagecache_flush_ops = {
    .flush = pagecache_flush,
    .is_dirty = pagecache_is_dirty,
    .set_dirty = pagecache_set_dirty,
};

struct page_cache_block *pagecache_create_cache_block(struct page *page, size_t size, size_t offset,
                                                      struct inode *file)
{
    struct page_cache_block *c = (page_cache_block *) zalloc(sizeof(struct page_cache_block));
    if (!c)
        return NULL;

    c->buffer = PAGE_TO_VIRT(page);
    c->page = page;
    c->node = file;
    c->size = size;
    c->offset = offset;
    c->fobj.ops = &pagecache_flush_ops;
    page->cache = c;
    used_cache_pages++;

#ifdef CONFIG_CHECK_PAGE_CACHE_INTEGRITY
    c->integrity = crc32_calculate(c->buffer, c->size);
#endif

    return c;
}

void pagecache_dirty_block(struct page_cache_block *block)
{
    struct page *page = block->page;

    unsigned long old_flags = __sync_fetch_and_or(&page->flags, PAGE_FLAG_DIRTY);

    if (old_flags & PAGE_FLAG_DIRTY)
        return;

    flush_add_buf(&block->fobj);
}

void pagecache_init(void)
{
    flush_init();
}

INIT_LEVEL_CORE_AFTER_SCHED_ENTRY(pagecache_init);

// FIXME: This never gets called
void page_cache_destroy(struct page_cache_block *block)
{
    // FIXME: Implement correctly
    free_page(block->page);
    used_cache_pages--;

    free(block);
}

size_t pagecache_get_used_pages(void)
{
    return used_cache_pages;
}
