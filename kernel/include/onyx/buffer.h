/*
* Copyright (c) 2020 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _ONYX_BUFFER_H
#define _ONYX_BUFFER_H

#include <onyx/page.h>
#include <onyx/list.h>
#include <onyx/block.h>

#include <onyx/mm/flush.h>

/* block_buf represents a filesystem block(works kind of like a buffer_head in linux).
 * It keeps information like whether the block is dirty, the page it's stored on, the offset, etc.
 * It's supposed to be used by filesystems only, for metadata.
 */

struct block_buf
{
	/* This block's refcount */
	unsigned long refc;
	/* The page it's stored on */
	struct page *this_page;
	/* This represents the next block_buf within the page */
	struct block_buf *next;
	/* The offset within the page */
	unsigned int page_off;
	/* Various flags - see below */
	unsigned int flags;
	/* The dirty list node, to be used when dirtying buffers */
	struct flush_object flush_obj;
	/* The corresponding block device */
	struct blockdev *dev;
	/* The block number */
	sector_t block_nr;
	/* The block size */
	unsigned int block_size;
};

#define BLOCKBUF_FLAG_DIRTY          (1 << 0)

#define MAX_BLOCK_SIZE				PAGE_SIZE

#ifdef __cplusplus
extern "C" {
#endif

struct superblock;

struct block_buf *page_add_blockbuf(struct page *page, unsigned int page_off);
struct block_buf *sb_read_block(struct superblock *sb, unsigned long block);
void block_buf_free(struct block_buf *buf);
struct page *bbuffer_commit(size_t off, struct vm_object *vmo);
void block_buf_dirty(struct block_buf *buf);

static inline void block_buf_get(struct block_buf *buf)
{
	__atomic_add_fetch(&buf->refc, 1, __ATOMIC_RELAXED);
	page_ref(buf->this_page);
}

static inline void block_buf_put(struct block_buf *buf)
{
	unsigned long result = __atomic_sub_fetch(&buf->refc, 1, __ATOMIC_RELAXED);
	page_unref(buf->this_page);

	if(result == 0)
		block_buf_free(buf);
}

static inline void *block_buf_data(struct block_buf *b)
{
	return (void *)(((unsigned long) PAGE_TO_VIRT(b->this_page)) + b->page_off);
}

#ifdef __cplusplus
}
#endif

#endif
