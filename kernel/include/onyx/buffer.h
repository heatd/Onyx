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
#define BLOCKBUF_FLAG_UNDER_WB       (1 << 1)

#define MAX_BLOCK_SIZE				PAGE_SIZE

#ifdef __cplusplus
extern "C" {
#endif

struct superblock;

struct block_buf *page_add_blockbuf(struct page *page, unsigned int page_off);
struct block_buf *sb_read_block(const struct superblock *sb, unsigned long block);
void block_buf_free(struct block_buf *buf);
void block_buf_writeback(struct block_buf *buf);
struct page *bbuffer_commit(size_t off, struct vm_object *vmo);
void block_buf_dirty(struct block_buf *buf);
struct block_buf *block_buf_from_page(struct page *p);
void page_destroy_block_bufs(struct page *page);

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

class auto_block_buf
{
private:
	block_buf *buf;
public:
	auto_block_buf() : buf{nullptr} {}
	auto_block_buf(block_buf *b) : buf{b} {}

	void unref() const
	{
		block_buf_put(buf);
	}

	void ref() const
	{
		block_buf_get(buf);
	}

	block_buf *release()
	{
		auto ret = buf;
		buf = nullptr;
		return ret;
	}

	void reset(block_buf *b)
	{
		if(buf)
			unref();
		buf = b;
	}

	auto_block_buf& operator=(auto_block_buf&& rhs)
	{
		if(this != &rhs)
			reset(rhs.release());
		return *this; 
	}

	auto_block_buf(auto_block_buf&& rhs)
	{
		if(this != &rhs)
		{
			buf = nullptr;
			reset(rhs.release());
		}
	}

	auto_block_buf& operator=(const auto_block_buf& rhs)
	{
		auto b = rhs.buf;

		if(this == &rhs)
			return *this;

		if(b)
			block_buf_get(b);

		reset(b);

		return *this;
	}

	auto_block_buf(const auto_block_buf& rhs)
	{
		auto b = rhs.buf;

		if(this == &rhs)
			return;

		if(b)
			block_buf_get(b);

		reset(b);

		return;
	}

	~auto_block_buf()
	{
		if(buf)
			unref();
	}

	operator bool() const
	{
		return buf != nullptr;
	}

	operator block_buf *() const
	{
		return buf;
	}
};

class buf_dirty_trigger
{
private:
	auto_block_buf &buf;
	bool dont_dirty;
public:
	buf_dirty_trigger(auto_block_buf &b) : buf{b}, dont_dirty{false} {}

	~buf_dirty_trigger()
	{
		if(!dont_dirty)
			block_buf_dirty(buf);
	}

	void explicit_dirty()
	{
		block_buf_dirty(buf);
		dont_dirty = true;
	}

	void do_not_dirty()
	{
		dont_dirty = true;
	}
};


#endif

#endif
