/*
* Copyright (c) 2020 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <stdio.h>
#include <errno.h>

#include <onyx/block.h>
#include <onyx/buffer.h>
#include <onyx/mm/pool.hpp>
#include <onyx/mm/flush.h>
#include <onyx/cpu.h>

memory_pool<block_buf, 0> block_buf_pool;

ssize_t block_buf_flush(flush_object *fo);
bool block_buf_is_dirty(flush_object *fo);
static void block_buf_set_dirty(bool dirty, flush_object *fo);

const struct flush_ops blockbuf_fops =
{
	.flush = block_buf_flush,
	.is_dirty = block_buf_is_dirty,
	.set_dirty = block_buf_set_dirty
};

#define block_buf_from_flush_obj(fo)    container_of(fo, block_buf, flush_obj)

ssize_t block_buf_flush(flush_object *fo)
{
	auto buf = block_buf_from_flush_obj(fo);

	sector_t disk_sect = (buf->block_nr * buf->block_size) / buf->dev->sector_size;

	struct page_iov vec;
	vec.length = buf->block_size;
	vec.page_off = buf->page_off;
	vec.page = buf->this_page;

	struct bio_req r{};
	r.nr_vecs = 1;
	r.sector_number = disk_sect;
	r.flags = BIO_REQ_WRITE_OP;

	r.vec = &vec;

	__atomic_fetch_or(&buf->flags, BLOCKBUF_FLAG_UNDER_WB, __ATOMIC_RELAXED);
	__atomic_fetch_or(&vec.page->flags, PAGE_FLAG_FLUSHING, __ATOMIC_RELAXED);

	if(bio_submit_request(buf->dev, &r) < 0)
		return -EIO;
#if 0
	printk("Flushed #%lu.\n", buf->block_nr);
#endif

	return buf->block_size;
}

bool block_buf_is_dirty(flush_object *fo)
{
	auto buf = block_buf_from_flush_obj(fo);

	return buf->flags & BLOCKBUF_FLAG_DIRTY;
}

extern "C"
block_buf *block_buf_from_page(struct page *p)
{
	return reinterpret_cast<block_buf *>(p->priv);
}

bool page_has_dirty_bufs(struct page *p)
{
	auto buf = reinterpret_cast<block_buf *>(p->priv);
	bool has_dirty_buf = false;

	while(buf)
	{
		if(buf->flags & BLOCKBUF_FLAG_DIRTY)
		{
			has_dirty_buf = true;
			break;
		}

		buf = buf->next;
	}

	return has_dirty_buf;
}

static void block_buf_set_dirty(bool dirty, flush_object *fo)
{
	auto buf = block_buf_from_flush_obj(fo);
	auto page = buf->this_page;

	if(dirty)
	{
		while(buf->flags & BLOCKBUF_FLAG_UNDER_WB)
			cpu_relax();

		unsigned long old_flags = __atomic_fetch_or(&buf->flags, BLOCKBUF_FLAG_DIRTY, __ATOMIC_RELAXED);
		__atomic_fetch_or(&page->flags, PAGE_FLAG_DIRTY, __ATOMIC_RELAXED);

		if(!(old_flags & BLOCKBUF_FLAG_DIRTY))
		{
			flush_add_buf(fo);
		}
	}
	else
	{

	#if 0
		printk("unset dirty block #%lu\n", buf->block_nr);
	#endif
		__atomic_and_fetch(&buf->flags, ~(BLOCKBUF_FLAG_DIRTY | BLOCKBUF_FLAG_UNDER_WB), __ATOMIC_RELAXED);
		if(!page_has_dirty_bufs(page))
			__atomic_and_fetch(&page->flags, ~(PAGE_FLAG_DIRTY | PAGE_FLAG_FLUSHING), __ATOMIC_RELAXED);
	}
}

extern "C" struct block_buf *page_add_blockbuf(struct page *page, unsigned int page_off)
{
	assert(page->flags & PAGE_FLAG_BUFFER);

	auto buf = block_buf_pool.allocate();
	if(!buf)
	{
		return nullptr;
	}

	buf->page_off = page_off;
	buf->this_page = page;
	buf->next = nullptr;
	buf->flush_obj.ops = &blockbuf_fops;
	buf->refc = 1;
	buf->flags = 0;

	/* It's better to do this naively using O(n) as to keep memory usage per-struct page low. */
	block_buf **pp = reinterpret_cast<block_buf **>(&page->priv);

	while(*pp)
		pp = &(*pp)->next;

	*pp = buf;

	return buf;
}

void block_buf_remove(struct block_buf *buf)
{
	struct page *page = buf->this_page;

	block_buf **pp = reinterpret_cast<block_buf **>(&page->priv);

	while(*pp)
	{
		block_buf *b = *pp;
		if(b == buf)
		{
			*pp = buf->next;
			break;
		}

		pp = &(*pp)->next;
	}
}

extern "C"
void block_buf_writeback(struct block_buf *buf)
{
	flush_sync_one(&buf->flush_obj);
}

extern "C" void block_buf_free(struct block_buf *buf)
{
	if(buf->flags & BLOCKBUF_FLAG_DIRTY)
		block_buf_writeback(buf);

	block_buf_remove(buf);

	block_buf_pool.free(buf);
}

extern "C"
void page_destroy_block_bufs(struct page *page)
{
	auto b = reinterpret_cast<block_buf *>(page->priv);

	block_buf *next = nullptr;

	while(b)
	{
		next = b->next;

		block_buf_free(b);

		b = next;
	}
}

/* Hmmm - I don't like this. Like linux, We're limiting ourselves to
 * block_size <= page_size here...
 */

extern "C"
vmo_status_t bbuffer_commit(vm_object *vmo, size_t off, page **ppage)
{
	vmo_status_t st = VMO_STATUS_BUS_ERROR;

	page *p = alloc_page(PAGE_ALLOC_NO_ZERO);
	if(!p)
		return VMO_STATUS_OUT_OF_MEM;
	p->flags |= PAGE_FLAG_BUFFER;
	
	auto blkdev = reinterpret_cast<blockdev*>(vmo->priv);

	sector_t sec_nr = off / blkdev->sector_size;

	if(off % blkdev->sector_size)
	{
		free_page(p);
		printf("bbuffer_commit: Cannot read unaligned offset %lu\n", off);
		return VMO_STATUS_BUS_ERROR;
	}

	auto sb = blkdev->sb;

	assert(sb != nullptr);

	struct page_iov vec;
	vec.length = PAGE_SIZE;
	vec.page = p;
	vec.page_off = 0;

	struct bio_req r{};
	r.nr_vecs = 1;
	r.vec = &vec;
	r.sector_number = sec_nr;
	r.flags = BIO_REQ_READ_OP;

	auto block_size = sb->s_block_size;
	auto nr_blocks = PAGE_SIZE / block_size;
	size_t starting_block_nr = off / block_size;

	size_t curr_off = 0;

	int iost = bio_submit_request(blkdev, &r);
	if(iost < 0)
		goto error;
	
	for(size_t i = 0; i < nr_blocks; i++)
	{
		struct block_buf *b;
		if(!(b = page_add_blockbuf(p, curr_off)))
		{
			page_destroy_block_bufs(p);
			st = VMO_STATUS_OUT_OF_MEM;
			goto error;
		}

		b->block_nr = starting_block_nr + i;
		b->block_size = block_size;
		b->dev = blkdev;
	
		curr_off += block_size;
	}

	*ppage = p;

	return VMO_STATUS_OK;

error:
	free_page(p);
	return st;
}

extern "C" struct block_buf *sb_read_block(const struct superblock *sb, unsigned long block)
{
	struct blockdev *dev = sb->s_bdev;
	size_t real_off = sb->s_block_size * block;
	size_t aligned_off = real_off & -PAGE_SIZE;

	struct page *page;
	
	auto st = vmo_get(dev->vmo, aligned_off, VMO_GET_MAY_POPULATE, &page);

	if(st != VMO_STATUS_OK)
		return nullptr;
	
	auto buf = reinterpret_cast<block_buf *>(page->priv);

	while(buf && buf->block_nr != block)
	{
		buf = buf->next;
	}

	if(unlikely(!buf))
	{
		size_t page_off = real_off - aligned_off;
		sector_t aligned_block = aligned_off / sb->s_block_size;
#if 0
		printk("Aligned block: %lx\n", aligned_block);
		printk("Aligned off %lx real off %lx\n", aligned_off, real_off);
#endif
		sector_t block_nr = aligned_block + ((real_off - aligned_off) / sb->s_block_size);

		if(!(buf = page_add_blockbuf(page, page_off)))
		{
			page_unref(page);
			return nullptr;
		}

		buf->block_nr = block_nr;
		buf->block_size = sb->s_block_size;
		buf->dev = sb->s_bdev;
	}
	
	block_buf_get(buf);

	page_unref(page);

	return buf;
}

struct sb
{
	uint32_t s_inodes_count;
	uint32_t s_blocks_count;
	uint32_t s_r_blocks_count;
	uint32_t s_free_blocks_count;
	uint32_t s_free_inodes_count;
	uint32_t s_first_data_block;
	uint32_t s_log_block_size;
	uint32_t s_log_frag_size;
	uint32_t s_blocks_per_group;
	uint32_t s_frags_per_group;
	uint32_t s_inodes_per_group;
	uint32_t s_mtime;
	uint32_t s_wtime;
	uint16_t s_mnt_count;
	uint16_t s_max_mnt_count;
	uint16_t s_magic;
};

void block_buf_dirty(block_buf *buf)
{
	if(buf->block_nr == 0)
	{
		sb *s = (sb *) ((char *) block_buf_data(buf) + 1024);
		assert(s->s_magic == 0xef53);
	}

	block_buf_set_dirty(true, &buf->flush_obj);
}

void page_remove_block_buf(struct page *page, size_t offset, size_t end)
{
	block_buf **pp = (block_buf **) &page->priv;

	while(*pp != nullptr)
	{
		if((*pp)->page_off >= offset && (*pp)->page_off < end)
		{
			auto bbuf = *pp;
			*pp = (*pp)->next;
			block_buf_free(bbuf);
		}
		else
			pp = &(*pp)->next;
	}
}
