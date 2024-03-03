/*
 * Copyright (c) 2024 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
#include <onyx/bio.h>
#include <onyx/block.h>
#ifdef CONFIG_KUNIT
#include <onyx/kunit.h>
#include <onyx/vm.h>
#endif

/**
 * @brief Check if a given bio is valid
 *
 * @param bio Bio to check
 * @param qp Queue properties to check
 * @return True if valid (adding this to a struct request should work), else false
 */
static bool bio_is_valid_internal(struct bio_req *bio, struct queue_properties *qp)
{
    size_t length = 0;

    if (bio->nr_vecs > qp->max_sgls_per_request)
        return false;

    for (size_t i = 0; i < bio->nr_vecs; i++)
    {
        const struct page_iov *iov = &bio->vec[i];
        u64 address = ((u64) page_to_phys(iov->page)) + iov->page_off;
        u64 end = address + iov->length;
        /* Check for dma_address_mask (for every segment) */
        if (address & qp->dma_address_mask || end & qp->dma_address_mask)
            return false;
        /* Check the length */
        if (iov->length > qp->max_sgl_desc_length)
            return false;

        /* Check the inter sgl boundaries (if needed). Segments that have a segment before it need
         * to have their head checked, segments that have something after it need to have their tail
         * checked. */
        if (i > 0)
        {
            if (address & qp->inter_sgl_boundary_mask)
                return false;
        }

        if (i != bio->nr_vecs - 1)
        {
            /* Not the last sgl segment, check the tail */
            if (end & qp->inter_sgl_boundary_mask)
                return false;
        }

        length += iov->length;
    }

    /* TODO: have length as a full-time member of struct bio_req. Should be easily doable after we
     * finish up refactoring bio_req and eliminating device_specific (even without that,
     * device_specific[3] is unused and could be repurposed). */
    return length / 512 <= qp->max_sectors_per_request;
}

/**
 * @brief Check if a given bio is valid (wrt the block device)
 *
 * @param bio Bio to check
 * @return True if valid (adding this to a struct request should work), else false
 */
bool bio_is_valid(struct bio_req *bio)
{
    blockdev *bdev = bio->bdev;
    return bio_is_valid_internal(bio, &bdev->bdev_queue_properties);
}

#ifdef CONFIG_KUNIT

TEST(bio, basic_valid_bios_are_valid)
{
    struct queue_properties qp;
    bdev_set_default_queue_properties(qp);

    /* Very simple tests for very simple requests that *should* always be supported with the default
     * queue properties. The only limitation that is imposed by default is dma_address_mask = 511
     * (must be sector-aligned) */
    struct page *test_page = vm_get_zero_page();
    struct bio_req *bio = bio_alloc(GFP_KERNEL, 3);
    ASSERT_NONNULL(bio);

    /* Page-sized requests */
    for (int i = 0; i < 3; i++)
        bio->vec[i] = page_iov{test_page, PAGE_SIZE, 0};

    EXPECT_TRUE(bio_is_valid_internal(bio, &qp));

    /* Sector sized requests (no offset) */
    for (int i = 0; i < 3; i++)
        bio->vec[i] = page_iov{test_page, 512, 0};

    EXPECT_TRUE(bio_is_valid_internal(bio, &qp));

    /* Sector sized requests, sector aligned */
    for (int i = 0; i < 3; i++)
        bio->vec[i] = page_iov{test_page, 512, 512u * i};

    EXPECT_TRUE(bio_is_valid_internal(bio, &qp));

    /* Variable-sized page_iovs (with variable length, sector aligned), sector aligned page offsets
     */
    for (int i = 0; i < 3; i++)
        bio->vec[i] = page_iov{test_page, i * 512u, i * 512u};

    EXPECT_TRUE(bio_is_valid_internal(bio, &qp));

    bio_put(bio);
}

static struct queue_properties nvme_queue_properties()
{
    /* NVMe is a funny spec with some funny limitations. This represents those limitations in a PRP
     * setup. */
    struct queue_properties qp;
    bdev_set_default_queue_properties(qp);
    qp.inter_sgl_boundary_mask = PAGE_SIZE - 1;
    qp.max_sectors_per_request = 0xffff;
    qp.dma_address_mask = 3;
    return qp;
}

TEST(bio, nvme_valid_bios_are_valid)
{
    struct queue_properties qp = nvme_queue_properties();

    /* Very simple tests for very simple requests that are supported by NVMe.
     * Queue limitations:
     * - dma_address_mask = 3 (must be dword-aligned)
     * - max_sectors_per_request 0xffff
     * - inter_sgl_boundary_mask = PAGE_SIZE - 1 (must not have page offsets "between" sgl descs) */
    struct page *test_page = vm_get_zero_page();
    struct bio_req *bio = bio_alloc(GFP_KERNEL, 3);
    ASSERT_NONNULL(bio);

    /* Page-sized requests */
    for (int i = 0; i < 3; i++)
        bio->vec[i] = page_iov{test_page, PAGE_SIZE, 0};

    EXPECT_TRUE(bio_is_valid_internal(bio, &qp));

    /* 512 bytes - PAGE - PAGE */
    bio->vec[0] = page_iov{test_page, 512, PAGE_SIZE - 512};
    bio->vec[1] = page_iov{test_page, PAGE_SIZE, 0};
    bio->vec[2] = page_iov{test_page, PAGE_SIZE, 0};

    EXPECT_TRUE(bio_is_valid_internal(bio, &qp));

    /* 512 bytes - PAGE - (PAGE - 1 sector) */
    bio->vec[0] = page_iov{test_page, 512, PAGE_SIZE - 512};
    bio->vec[1] = page_iov{test_page, PAGE_SIZE, 0};
    bio->vec[2] = page_iov{test_page, PAGE_SIZE - 512, 0};

    EXPECT_TRUE(bio_is_valid_internal(bio, &qp));

    bio_put(bio);

    bio = bio_alloc(GFP_KERNEL, 1);
    ASSERT_NONNULL(bio);

    /* 1 sgl, 1024 bytes (this is a valid PRP entry for an NVMe request) */
    bio->vec[0] = page_iov{test_page, 1024, 4};
    EXPECT_TRUE(bio_is_valid_internal(bio, &qp));
    bio_put(bio);
}

TEST(nvme, nvme_invalid_bios_are_invalid)
{
    struct queue_properties qp = nvme_queue_properties();

    /* Very simple tests for very simple requests that are supported by NVMe.
     * Queue limitations:
     * - dma_address_mask = 3 (must be dword-aligned)
     * - max_sectors_per_request 0xffff
     * - inter_sgl_boundary_mask = PAGE_SIZE - 1 (must not have page offsets "between" sgl descs) */
    struct page *test_page = vm_get_zero_page();
    struct bio_req *bio = bio_alloc(GFP_KERNEL, 3);
    ASSERT_NONNULL(bio);

    /* Misaligned address (not dword aligned) at SGL 2. */
    bio->vec[0] = page_iov{test_page, PAGE_SIZE, 0};
    bio->vec[1] = page_iov{test_page, PAGE_SIZE, 0};
    bio->vec[2] = page_iov{test_page, 512, 2};

    EXPECT_FALSE(bio_is_valid_internal(bio, &qp));

    /* PAGE - partial page - PAGE (tests inter_sgl_boundary_mask at an SGL tail) */
    bio->vec[0] = page_iov{test_page, PAGE_SIZE, 0};
    bio->vec[1] = page_iov{test_page, 512, 0};
    bio->vec[2] = page_iov{test_page, PAGE_SIZE, 0};

    EXPECT_FALSE(bio_is_valid_internal(bio, &qp));

    /* PAGE - PAGE - partial PAGE (tests inter_sgl_boundary_mask at an SGL head) */
    bio->vec[0] = page_iov{test_page, PAGE_SIZE, 0};
    bio->vec[1] = page_iov{test_page, 512, 0};
    bio->vec[2] = page_iov{test_page, PAGE_SIZE, 0};

    EXPECT_FALSE(bio_is_valid_internal(bio, &qp));

    bio_put(bio);

    /* Test max_sectors_per_request by submitting a request with certainly more than 0x10000 sectors
     */
    bio = bio_alloc(GFP_KERNEL, 0x10000);
    ASSERT_NONNULL(bio);

    for (int i = 0; i < 0x10000; i++)
        bio->vec[i] = page_iov{test_page, PAGE_SIZE, 0};

    EXPECT_FALSE(bio_is_valid_internal(bio, &qp));

    bio_put(bio);
}

TEST(bio, invalid_bios_are_invalid)
{
    struct queue_properties qp;
    bdev_set_default_queue_properties(qp);

    struct page *test_page = vm_get_zero_page();
    struct bio_req *bio = bio_alloc(GFP_KERNEL, 1);
    ASSERT_NONNULL(bio);

    /* dma_address_mask tests (for the head and tail) */
    /* Head misaligned */
    bio->vec[0] = page_iov{test_page, PAGE_SIZE, 1};
    EXPECT_FALSE(bio_is_valid_internal(bio, &qp));
    /* Tail misaligned */
    bio->vec[0] = page_iov{test_page, 1, 0};
    EXPECT_FALSE(bio_is_valid_internal(bio, &qp));

    /* Test sgl desc length rejection */
    qp.max_sgl_desc_length = 512;
    bio->vec[0] = page_iov{test_page, 1024, 0};
    EXPECT_FALSE(bio_is_valid_internal(bio, &qp));

    bio_put(bio);
}

#endif
