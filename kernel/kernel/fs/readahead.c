/*
 * Copyright (c) 2024 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <stdbool.h>
#include <stdio.h>

#include <onyx/block/blk_plug.h>
#include <onyx/filemap.h>
#include <onyx/vfs.h>

/* We implement a very simple readahead scheme. We maintain a readahead window (min 64KiB). When
 * doing readahead synchronously (we found a page !UPTODATE), we start reading that same page + the
 * readahead window, completely async. We set a marker (PAGE_FLAG_READAHEAD) in the middle of the RA
 * window. If (and when) we hit the marker, we double the RA window (up to 512KiB).
 *
 * Known limitations: We have no "random access" penalty, we only have readahead state in the struct
 * file (multiple mmaps of the same file will share RA state), block devices can't do readahead.
 * */
#define RA_MIN_WINDOW (0x10000 / PAGE_SIZE)

/**
 * @brief Get the next page out of the readpages state
 * The page will be returned locked.
 *
 * @param state Readpages state
 * @return Locked page, or NULL (if we can out of pages)
 */
struct page *readpages_next_page(struct readpages_state *state)
{
    struct page *page = NULL;
    if (state->nr_pages == 0)
        return NULL;

    /* TODO: This is inefficient */
    int st = filemap_find_page(state->ino, state->pgoff,
                               FIND_PAGE_NO_READPAGE | FIND_PAGE_NO_RA | FIND_PAGE_NO_CREATE, &page,
                               NULL);
    /* Note: We already hold the page locks, no need to re-acquire them */
    if (st < 0)
        DCHECK(st == 0);

    DCHECK(page != NULL && page_locked(page));
    state->nr_pages--;
    state->pgoff++;
    return page;
}

/**
 * @brief Finish the readpages process
 * All locked-but-not-read pages will be unlocked
 *
 * @param state Readpagse state
 */
static void readpages_finish(struct readpages_state *state) NO_THREAD_SAFETY_ANALYSIS
{
    /* For all the pages that weren't read, unlock and unref. Any subsequent access will notice the
     * !UPTODATE and try to read them in. */
    struct page *page;
    while ((page = readpages_next_page(state)))
    {
        unlock_page(page);
        page_unref(page);
    }
}

u64 bdev_get_size(struct blockdev *bdev);

static int filemap_do_readahead(struct inode *inode, struct readahead_state *ra_state,
                                unsigned long pgoff) NO_THREAD_SAFETY_ANALYSIS
{
    int st = 0;
    size_t size = inode->i_size;
    size_t endpg;
    struct blk_plug plug;

    if (S_ISBLK(inode->i_mode))
        size = bdev_get_size(inode->i_helper);

    /* Do basic bounds checks on our readahead window */
    if (!size)
        return 0;

    /* If we *can't* do readahead, do not even start the process */
    if (!inode->i_pages->ops->readpages)
        return 0;

    endpg = (size - 1) >> PAGE_SHIFT;
    if (endpg <= pgoff)
        return 0;

    unsigned long window = READ_ONCE(ra_state->ra_window);
    unsigned long start = pgoff;
    unsigned long mark;

    if (!window)
        window = RA_MIN_WINDOW;

    /* We must be careful not to get a window beyond the inode size */
    if (pgoff + window > endpg)
        window = endpg - pgoff;

    mark = pgoff + window / 2;

    /* For all pages after (including) pgoff, allocate pages (if required!) and later kick off IO */
    for (unsigned long i = 0; i < window; i++)
    {
        struct page *page = NULL;
        /* TODO: Using filemap_find_page here is inefficient */
        st = filemap_find_page(inode, pgoff + i,
                               FIND_PAGE_LOCK | FIND_PAGE_NO_READPAGE | FIND_PAGE_NO_RA, &page,
                               NULL);
        if (st < 0)
        {
            /* Oh no, lets backtrack */
            for (unsigned long j = 0; j < i; j++)
            {
                int st2 = filemap_find_page(
                    inode, pgoff + j, FIND_PAGE_NO_CREATE | FIND_PAGE_NO_READPAGE | FIND_PAGE_NO_RA,
                    &page, NULL);
                CHECK(st2 == 0);
                /* Unlock the page and unref */
                DCHECK(page_locked(page));
                unlock_page(page);
                page_unref(page);
            }

            goto out;
        }

        if (pgoff + i == mark)
            page->flags |= PAGE_FLAG_READAHEAD;
        DCHECK(page_locked(page));

        page_unref(page);
    }

    blk_start_plug(&plug);
    struct readpages_state state = {inode, pgoff, window};
    st = inode->i_pages->ops->readpages(&state, inode);
    readpages_finish(&state);
    if (likely(st == 0))
    {
        WRITE_ONCE(ra_state->ra_start, start);
        WRITE_ONCE(ra_state->ra_window, window);
        WRITE_ONCE(ra_state->ra_mark, mark);
    }

out:
    blk_end_plug(&plug);
    return st;
}

int filemap_do_readahead_sync(struct inode *inode, struct readahead_state *ra_state,
                              unsigned long pgoff)
{
    return filemap_do_readahead(inode, ra_state, pgoff);
}

int filemap_do_readahead_async(struct inode *inode, struct readahead_state *ra_state,
                               unsigned long pgoff)
{
    /* Okay, we found the PAGE_FLAG_READAHEAD page, time to kick off more IO */
    if (READ_ONCE(ra_state->ra_mark) != pgoff)
    {
        /* We must've found some other READAHEAD page, do not kick off IO */
        return 1;
    }

    unsigned long window = READ_ONCE(ra_state->ra_window);

    if (window < RA_MAX_WINDOW)
        WRITE_ONCE(ra_state->ra_window, window * 2);
    return filemap_do_readahead(inode, ra_state, READ_ONCE(ra_state->ra_start) + window * 2);
}
