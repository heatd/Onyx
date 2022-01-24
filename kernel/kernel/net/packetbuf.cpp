/*
 * Copyright (c) 2020 - 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#include <stdlib.h>
#include <errno.h>

#include <stdio.h>

#include <onyx/packetbuf.h>
#include <onyx/compiler.h>
#include <onyx/memory.hpp>

#include <onyx/mm/pool.hpp>

memory_pool<packetbuf, MEMORY_POOL_USABLE_ON_IRQ> packetbuf_pool;

void *packetbuf::operator new(size_t length)
{
	return packetbuf_pool.allocate();
}

void packetbuf::operator delete(void *ptr)
{
	packetbuf_pool.free(reinterpret_cast<packetbuf *>(ptr));
}

/**
 * @brief Reserve space for the packet.
 * This function is only meant to be called once, at initialisation,
 * and calling it again may make the kernel crash and burn.
 *
 * @param length The maximum length of the whole packet(including headers and footers)
 *
 * @return Returns true if it was successful, false if it was not.
 */
bool packetbuf::allocate_space(size_t length)
{
	/* This should only be called once - essentially,
	 * we allocate enough pages for the packet and fill page_vec.
	 */

	auto nr_pages = vm_size_to_pages(length);

	page *pages = alloc_pages(nr_pages, PAGE_ALLOC_NO_ZERO);
	if(!pages)
		return false;

	vmo = vmo_create(length, nullptr);
	if(!vmo)
	{
		free_pages(pages);
		return false;
	}

	auto pages_head = pages;

	for(size_t i = 0; i < nr_pages; i++)
	{
		page_ref(pages);

		if(vmo_add_page_unlocked(i << PAGE_SHIFT, pages, vmo) < 0)
		{
			free_pages(pages_head);
			vmo_destroy(vmo);
			return false;
		}

		page_vec[i].page = pages;

		if(i == 0)
		{
			page_vec[i].length = min(length, PAGE_SIZE);
		}
		else
		{
			page_vec[i].length = 0;
		}
		

		length -= page_vec[i].length;
		page_vec[i].page_off = 0;
		pages = pages->next_un.next_allocation;
	}

#if 0
	buffer_start = vm_map_vmo(VM_KERNEL, VM_TYPE_REGULAR, nr_pages, VM_WRITE | VM_NOEXEC | VM_READ, vmo);
	if(!buffer_start)
	{
		free_pages(pages_head);

		for(size_t i = 0; i < nr_pages; i++)
		{
			page_vec[i].reset();
		}

		vmo_destroy(vmo);
		vmo = nullptr;

		return false;
	}
#else
	buffer_start = PAGE_TO_VIRT(pages_head);
#endif

	net_header = transport_header = nullptr;
	data = tail = (unsigned char *) buffer_start;
	end = (unsigned char *) buffer_start + PAGE_SIZE;

	return true;
}

/**
 * @brief Reserve space for the headers.
 * 
 * @param header_length Length of the headers 
 */
void packetbuf::reserve_headers(unsigned int header_length)
{
	data += header_length;
	tail = data;
}

/**
 * @brief Get space for a networking header, and adjust data to point to the start of the header.
 * 
 * @param size Size of the header.
 *
 * @return void* The address of the new header.
 */
void *packetbuf::push_header(unsigned int header_length)
{
	assert((unsigned long) data >= (unsigned long) buffer_start);

	data -= header_length;

	return (void *) data;
}

/**
 * @brief Get space for data, and advance tail by size.
 * 
 * @param size The length of the data.
 *
 * @return void* The address of the new data.
 */
void *packetbuf::put(unsigned int size)
{
	auto to_ret = tail;

	tail += size;

	assert((unsigned long) tail <= (unsigned long) end);

	return to_ret;
}

/**
 * @brief Destroy the packetbuf object and free the backing pages.s
 * 
 */
packetbuf::~packetbuf()
{
	//const auto mapping_length = end - (unsigned char *) buffer_start;

	//if(buffer_start)   vm_munmap(&kernel_address_space, buffer_start, mapping_length);
	if(vmo)  vmo_unref(vmo);

	for(auto &v : page_vec)
	{
		if(v.page)
			free_page(v.page);
	}
}

/**
 * @brief Clones a packetbuf and returns a metadata-identical and data-identical copy.
 * 
 * @param original The original packetbuf.
 * @return The new packetbuf, or NULL if we ran out of memory.
 */
packetbuf *packetbuf_clone(packetbuf *original)
{
	unique_ptr buf = make_unique<packetbuf>();
	if(!buf)
		return nullptr;
	
	auto buf_len = original->start_page_off() + original->length();

	if(!buf->allocate_space(buf_len))
	{
		return nullptr;
	}

	memcpy(buf->buffer_start, original->buffer_start, buf_len);

	auto nhoff = original->net_header - (unsigned char *) original->buffer_start;
	auto thoff = original->transport_header - (unsigned char *) original->buffer_start;
	buf->reserve_headers(original->start_page_off());

	buf->net_header = (unsigned char *) buf->buffer_start + nhoff;
	buf->transport_header = (unsigned char *) buf->buffer_start + thoff;

	buf->put(original->length());
	buf->domain = original->domain;

	return buf.release();
}


static int allocate_page_vec(page_iov& v)
{
	page *p = alloc_page(0);

	if(!p)
		return -ENOMEM;
	
	v.length = 0;
	v.page = p;
	v.page_off = 0;

	return 0;
}

/**
 * @brief Expands the packet buffer, either by doing put(), expanding page iters, or adding new pages.
 * 
 * @param ubuf User address of the buffer.
 * @param len Length of the buffer.
 * @return The amount copied, or a negative error code if we failed to copy anything.
 */
ssize_t packetbuf::expand_buffer(const void *ubuf_, unsigned int len)
{
	//printk("len %u\n", len);
	ssize_t ret = 0;
	const uint8_t *ubuf = static_cast<const uint8_t *>(ubuf_);
	/* Right now, trying to expand a packetbuf with zero copy enabled would blow up spectacularly,
	 * since it could try to access random pages that may be allocated or something.
	 */
	assert(!zero_copy);

	if(can_try_put())
	{
		if(tail_room())
		{
			auto to_put = min(tail_room(), len);
			auto p = put(to_put);

			if(copy_from_user(p, ubuf, to_put) < 0)
				return -EFAULT;
			
			ubuf += to_put;
			len -= to_put;
			ret += to_put;
		}
#if DEBUG_PACKETBUF_GROW
		printk("Put %ld bytes in put()\n", ret);
#endif
	}

	for(unsigned int i = 1; i < PACKETBUF_MAX_NR_PAGES; i++)
	{
		if(!len)
			break;
		
		auto &v = page_vec[i];

		if(!v.page)
		{
			if(allocate_page_vec(v) < 0)
				return -ENOMEM;
		}

		unsigned int tail_room = PAGE_SIZE - v.length;

		if(tail_room > 0)
		{
			auto to_put = min(tail_room, len);

#if DEBUG_PACKETBUF_GROW
			printk("length %u + tail room %u = %u", length(), tail_room, length() + tail_room);
#endif
			uint8_t *dest_ptr = (uint8_t *) PAGE_TO_VIRT(v.page) + v.page_off + v.length;

			if(copy_from_user(dest_ptr, ubuf, to_put) < 0)
				return -EFAULT;
#if DEBUG_PACKETBUF_GROW
			printk("Put %u bytes in page vec %u\n", to_put, i);
#endif

			v.length += to_put;
			ubuf += to_put;
			len -= to_put;
			ret += to_put;
		}
	}

	return ret;
}
