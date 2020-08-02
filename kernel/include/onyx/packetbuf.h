/*
* Copyright (c) 2020 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _ONYX_PACKETBUF_H
#define _ONYX_PACKETBUF_H

#include <stddef.h>
#include <limits.h>

#include <onyx/page.h>
#include <onyx/page_iov.h>

#define PACKETBUF_MAX_NR_PAGES    (UINT16_MAX / PAGE_SIZE)

#define DEFAULT_HEADER_LEN        128

struct vm_object;

#define PACKETBUF_GSO_TSO4          (1 << 0)
#define PACKETBUF_GSO_TSO6          (1 << 1)
#define PACKETBUF_GSO_UFO           (1 << 2)

struct packetbuf
{
	/* Reasoning behind this - We're going to need at
	 * most 64KiB of space for the buffer, since that's the most we'll
	 * be able to buffer in one packet, for mostly technical but also practical reasons.
	 * So, we're getting 'x' number of iovs for the packet's data and 2 more;
	 * 1 is used as header data, because IF we're using zero-copy networking
	 * there will be inevitably a gap between the headers(which should span at most from
	 * [0 ... 120's...] and the end of the page.
	 * The other iov is used as a terminating canary.
	 */

	struct page_iov page_vec[PACKETBUF_MAX_NR_PAGES + 2];

	unsigned char *net_header;
	unsigned char *transport_header;
	unsigned char *data;
	unsigned char *tail;
	unsigned char *end;

	void *buffer_start;

	uint16_t *csum_offset;
	unsigned char *csum_start;
	vm_object *vmo;

	unsigned int header_length;
	uint16_t gso_size;

	uint8_t gso_flags;

	unsigned int needs_csum : 1;
	unsigned int zero_copy : 1;

	/**
	 * @brief Construct a new default packetbuf object.
	 * 
	 */
	packetbuf() : page_vec{}, net_header{}, transport_header{}, data{}, tail{},
	              end{}, buffer_start{}, csum_offset{nullptr}, csum_start{nullptr},
				  vmo{}, header_length{}, gso_size{}, gso_flags{}, needs_csum{0}, zero_copy{0} {}
	
	~packetbuf();

	void *operator new(size_t length);
	void operator delete(void *ptr);

	/**
	 * @brief Reserve space for the packet.
	 * This function is only meant to be called once, at initialisation,
	 * and calling it again may make the kernel crash and burn.
	 * @param length the maximum length of the whole packet(including headers and footers)
	 * @return true if it was successful, false if it was not.
	 */
	bool allocate_space(size_t length);

	/**
	 * @brief Reserve space for the headers.
	 * 
	 * @param header_length length of the headers 
	 */
	void reserve_headers(unsigned int header_length);

	/**
	 * @brief Get space for a networking header, and adjust data to point to the start of the header
	 * 
	 * @param size size of the header
	 * @return void* the address of the new header
	 */
	void *push_header(unsigned int size);

	/**
	 * @brief Get space for data, and advance tail by size
	 * 
	 * @param size the length of the data
	 * @return void* the address of the new data
	 */
	void *put(unsigned int size);

	unsigned int length() const
	{
		return tail - data;
	}

	unsigned int start_page_off() const
	{
		return data - (unsigned char *) buffer_start;
	}

	unsigned int transport_header_off() const
	{
		return transport_header - data; 
	}

	unsigned int net_header_off() const
	{
		return net_header - data;
	}

	unsigned int csum_offset_bytes() const
	{
		return (unsigned char *) csum_offset - data;
	}
};

#define PACKET_MAX_HEAD_LENGTH		128

#ifdef __cplusplus
extern "C" {
#endif


#ifdef __cplusplus
}
#endif

#endif
