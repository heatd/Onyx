/*
 * Copyright (c) 2024 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
#include <onyx/bio.h>

static void free_bounce_pages(struct page *page, int order)
{
    // TODO: HACK! Make the page allocator able to directly free higher order pages
    size_t pages = 1UL << order;

    while (pages--)
        free_page(page++);
}

static void bio_bounce_buf_free(struct bio_req *bio)
{
    for (size_t i = 0; i < bio->nr_vecs; i++)
    {
        struct page_iov *iov = &bio->vec[i];
        free_bounce_pages(iov->page, pages2order(vm_size_to_pages(iov->length)));
    }
}

static void bio_bounce_buf_endio_write(struct bio_req *bio)
{
    bio_bounce_buf_free(bio);
    bio_complete_cloned(bio);
}

static void bio_bounce_buf_endio_read(struct bio_req *bio)
{
    struct bio_req *original = bio_chained(bio);
    if ((bio->flags & BIO_STATUS_MASK) == BIO_REQ_DONE)
    {
        DCHECK(original->nr_vecs == bio->nr_vecs);
        for (size_t i = 0; i < original->nr_vecs; i++)
        {
            struct page_iov *dest = &original->vec[i];
            struct page_iov *src = &bio->vec[i];
            DCHECK(dest->page_off == src->page_off);
            DCHECK(dest->length == src->length);
            memcpy(PAGE_TO_VIRT(dest->page) + dest->page_off,
                   PAGE_TO_VIRT(src->page) + src->page_off, dest->length);
        }
    }

    bio_bounce_buf_free(bio);
    bio_complete_cloned(bio);
}

/**
 * @brief Bounce a BIO out of high mem
 *
 * @param original Original BIO to bounce
 * @param gfp_mask Mask (that limits our memory allocation)
 * @return New BIO (with bounced, valid buffers)
 */
struct bio_req *bio_bounce(struct bio_req *original, unsigned int gfp_mask)
{
    bool host2device;
    size_t i;
    struct bio_req *bio = bio_clone(original, gfp_mask);
    if (!bio)
        return NULL;

    /* Bounce 64-bit addresses to 32-bit addresses.
     * Note: We bounce *every page*, regardless if they're within the 32-bit limits or outside. Why?
     * Because it's very unlikely there's a bio with pages very far away, because code gets way
     * simpler, and because this is for all intents and purposes a fallback path. */

    /* host -> device requests need a memcpy before the command submission. device -> host need a
     * memcpy after the request completes. */
    host2device = bio->flags & BIO_REQ_WRITE_OP;

    for (i = 0; i < bio->nr_vecs; i++)
    {
        struct page_iov *iov = &bio->vec[i];
        unsigned long start = (unsigned long) page_to_phys(iov->page) + iov->page_off;
        size_t required_pages = vm_size_to_pages(iov->length);
        struct page *pages =
            alloc_pages(pages2order(required_pages),
                        (GFP_KERNEL | PAGE_ALLOC_4GB_LIMIT) & (gfp_mask | PAGE_ALLOC_4GB_LIMIT));
        if (!pages)
            goto enomem;
        iov->page = pages;

        if (host2device)
            memcpy(PAGE_TO_VIRT(pages) + iov->page_off, PHYS_TO_VIRT(start), iov->length);
    }

    if (host2device)
        bio->b_end_io = bio_bounce_buf_endio_write;
    else
        bio->b_end_io = bio_bounce_buf_endio_read;

    return bio;

enomem:
    for (size_t j = 0; j < i; j++)
    {
        struct page_iov *iov = &bio->vec[j];
        free_bounce_pages(iov->page, pages2order(vm_size_to_pages(iov->length)));
    }

    bio_put(bio);
    return NULL;
}
