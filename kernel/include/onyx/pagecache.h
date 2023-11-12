/*
 * Copyright (c) 2016 - 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef _PAGECACHE_H
#define _PAGECACHE_H

#include <onyx/list.h>
#include <onyx/mm/flush.h>
#include <onyx/mutex.h>
#include <onyx/paging.h>
#include <onyx/vfs.h>
#include <onyx/vm.h>

#define PAGE_CACHE_SIZE    PAGE_SIZE
#define FILE_CACHING_WRITE (1 << 0)

ssize_t file_write_cache(void *buffer, size_t len, struct inode *file, size_t offset);
ssize_t file_read_cache(void *buffer, size_t len, struct inode *file, size_t off);
ssize_t file_write_cache_unlocked(void *buffer, size_t len, struct inode *ino, size_t offset);

#endif
