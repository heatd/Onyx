/*
* Copyright (c) 2020 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
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

bool packetbuf::allocate_space(size_t length)
{
	/* This should only be called once - essentially,
	 * we allocate enough pages for the packet and fill page_vec.
	 */
	assert(length <= UINT16_MAX);

	auto nr_pages = vm_size_to_pages(length);
	const auto original_length = length;

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

		if(vmo_add_page(i << PAGE_SHIFT, pages, vmo) < 0)
		{
			free_pages(pages_head);
			vmo_destroy(vmo);
			return false;
		}

		page_vec[i].page = pages;
		page_vec[i].length = min(length, PAGE_SIZE);
		length -= page_vec[i].length;
		page_vec[i].page_off = 0;
		pages = pages->next_un.next_allocation;
	}

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

	net_header = transport_header = nullptr;
	data = tail = (unsigned char *) buffer_start;
	end = (unsigned char *) buffer_start + original_length;

	return true;
}

void packetbuf::reserve_headers(unsigned int header_length)
{
	data += header_length;
	tail = data;
}

void *packetbuf::push_header(unsigned int header_length)
{
	assert((unsigned long) data >= (unsigned long) buffer_start);

	data -= header_length;

	return (void *) data;
}

void *packetbuf::put(unsigned int size)
{
	auto to_ret = tail;

	tail += size;

	assert((unsigned long) tail <= (unsigned long) end);

	return to_ret;
}

packetbuf::~packetbuf()
{
	const auto mapping_length = end - (unsigned char *) buffer_start;

	if(buffer_start)   vm_munmap(&kernel_address_space, buffer_start, mapping_length);
	if(vmo)  vmo_unref(vmo);

	for(auto &v : page_vec)
	{
		if(v.page)
			free_page(v.page);
	}
}

packetbuf *packetbuf_clone(packetbuf *original)
{
	unique_ptr buf = make_unique<packetbuf>();
	if(!buf)
		return nullptr;
	
	auto buf_len = original->buffer_start_off() + original->length();

	if(!buf->allocate_space(buf_len))
	{
		return nullptr;
	}

	memcpy(buf->buffer_start, original->buffer_start, buf_len);

	buf->reserve_headers(original->buffer_start_off());

	buf->net_header = (unsigned char *) buf->buffer_start + original->net_header_off();
	buf->transport_header = (unsigned char *) buf->buffer_start + original->transport_header_off();

	buf->put(original->length());
	buf->domain = original->domain;

	return buf.release();
}
