/*
 * Copyright (c) 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef _ONYX_FILEMAP_H
#define _ONYX_FILEMAP_H

#include <stddef.h>

#include <onyx/iovec_iter.h>
#include <onyx/types.h>
#include <onyx/vfs.h>

struct file;
struct page;

/**
 * @brief Read from a generic file (using the page cache) using iovec_iter
 *
 * @param filp File pointer
 * @param off Offset
 * @param iter Iterator
 * @param flags Flags
 * @return Read bytes, or negative error code
 */
ssize_t filemap_read_iter(struct file *filp, size_t off, iovec_iter *iter, unsigned int flags);

/**
 * @brief Write to a generic file (using the page cache) using iovec_iter
 *
 * @param filp File pointer
 * @param off Offset
 * @param iter Iterator
 * @param flags Flags
 * @return Written bytes, or negative error code
 */
ssize_t filemap_write_iter(struct file *filp, size_t off, iovec_iter *iter, unsigned int flags);

#define FILEMAP_MARK_DIRTY RA_MARK_0

#define FIND_PAGE_NO_CREATE (1 << 0)
#define FIND_PAGE_LOCK      (1 << 1)

int filemap_find_page(struct inode *ino, size_t pgoff, unsigned int flags, struct page **outp);

void page_start_writeback(struct page *page, struct inode *inode)
    EXCLUDES(inode->i_pages->page_lock) REQUIRES(page);

void page_end_writeback(struct page *page, struct inode *inode) EXCLUDES(inode->i_pages->page_lock)
    REQUIRES(page);

/**
 * @brief Marks a page dirty in the filemap
 *
 * @param ino Inode to mark dirty
 * @param page Page to mark dirty
 * @param pgoff Page offset
 * @invariant page is locked
 */
void filemap_mark_dirty(struct inode *ino, struct page *page, size_t pgoff) REQUIRES(page);

struct writepages_info;

int filemap_writepages(struct inode *inode, struct writepages_info *wpinfo);

#define FILEMAP_MARK_DIRTY     RA_MARK_0
#define FILEMAP_MARK_WRITEBACK RA_MARK_1

#endif
