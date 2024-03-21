/*
 * Copyright (c) 2024 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
#include <onyx/block.h>
#include <onyx/block/blk_plug.h>
#include <onyx/block/request.h>
#include <onyx/mm/slab.h>
#ifdef CONFIG_KUNIT
#include <onyx/array.h>
#include <onyx/kunit.h>
#include <onyx/vm.h>
#endif

static inline struct bio_req *request_get_head(struct request *req)
{
    DCHECK(!list_is_empty(&req->r_bio_list));
    return container_of(list_first_element(&req->r_bio_list), struct bio_req, list_node);
}

static inline struct bio_req *request_get_tail(struct request *req)
{
    DCHECK(!list_is_empty(&req->r_bio_list));
    return container_of(list_last_element(&req->r_bio_list), struct bio_req, list_node);
}

enum merge_type
{
    MERGE_FRONT,
    MERGE_BACK
};

static void request_add_bio_head(struct request *req, struct bio_req *bio)
{
    list_add(&bio->list_node, &req->r_bio_list);
    req->r_nr_sgls += bio->nr_vecs;
}

static void request_add_bio_tail(struct request *req, struct bio_req *bio)
{
    list_add_tail(&bio->list_node, &req->r_bio_list);
    req->r_nr_sgls += bio->nr_vecs;
}

/**
 * @brief Allocate a request and fill it in with the bio
 *
 * @param bio BIO to use for the request
 * @return Allocated request, or NULL
 */
struct request *bio_req_to_request(struct bio_req *bio)
{
    struct request *req;
    struct blockdev *bdev = bio->bdev;
    DCHECK(bdev);

    /* If the block device provides a request kmem cache, use that */
    if (bdev->bdev_queue_properties.request_cache)
        req = (struct request *) kmem_cache_alloc(bdev->bdev_queue_properties.request_cache,
                                                  GFP_NOIO);
    else
        req = (struct request *) kmalloc(
            sizeof(struct request) + bdev->bdev_queue_properties.request_extra_headroom, GFP_NOIO);
    if (req) [[likely]]
    {
        bio_request_init(req);
        req->r_bdev = bdev;
        req->r_flags = bio->flags;
        req->r_queue = bio->b_queue;
        req->r_sector = bio->sector_number;
        /* Append this request to the head */
        request_add_bio_head(req, bio);
        size_t len = 0;
        for (size_t i = 0; i < bio->nr_vecs; i++)
            len += bio->vec[i].length;

        req->r_nsectors = len / 512;
    }

    return req;
}

/**
 * @brief Free a request struct
 *
 * @param req Request to free
 */
void block_request_free(struct request *req)
{
    struct blockdev *bdev = req->r_bdev;
    struct slab_cache *cache = bdev->bdev_queue_properties.request_cache;

    if (cache)
        kmem_cache_free(cache, req);
    else
        kfree(req);
}

static int block_do_merge(struct request *req, struct bio_req *bio, size_t bio_sectors,
                          enum merge_type merge_type)
{
    struct bio_req *old;
    struct blockdev *bdev = req->r_bdev;
    const struct queue_properties *qp = &bdev->bdev_queue_properties;
    /* Check if we will exceed the block device's max sectors per request */
    if (req->r_nsectors + bio_sectors > qp->max_sectors_per_request)
        return -EIO;

    /* Check that we wont go over the number of possible SGL descriptors for the hardware. Note that
     * unfortunately we can't merge SGL descriptors between bios. */
    if (req->r_nr_sgls + bio->nr_vecs > qp->max_sgls_per_request)
        return -EIO;

    /* Lets attempt to merge. Different checks happen to different merge types. Note that the bio
     * should have already went through the normal queue properties checks.
     *
     * One big specific check needs to happen here: we need to check against
     * qp::inter_sgl_boundary_mask for if the request continues to be valid (for the hardware) after
     * we prepend or append this bio. What to check depends on the merge type: front merges check
     * the validity of the end of the new bio and the validity of the start of the request's "old
     * head"; back merges do the same check for the tail of the old tail bio, and the head of the
     * new bio. */

    if (merge_type == MERGE_FRONT)
    {
        /* check the validity of the end of the new bio and the validity of the start of the
         * request's "old head" */
        struct page_iov *v = &bio->vec[bio->nr_vecs - 1];
        u64 address = (u64) (page_to_phys(v->page)) + v->page_off + v->length;
        if (address & qp->inter_sgl_boundary_mask)
            return -EIO;

        old = request_get_head(req);
        v = &old->vec[0];
        address = (u64) (page_to_phys(v->page)) + v->page_off;
        if (address & qp->inter_sgl_boundary_mask)
            return -EIO;
    }
    else
    {
        /* back merge: check for the tail of the old tail bio, and the head of the
         * new bio. */
        old = request_get_tail(req);
        struct page_iov *v = &old->vec[bio->nr_vecs - 1];
        u64 address = (u64) (page_to_phys(v->page)) + v->page_off + v->length;
        if (address & qp->inter_sgl_boundary_mask)
            return -EIO;

        v = &bio->vec[0];
        address = (u64) (page_to_phys(v->page)) + v->page_off;
        if (address & qp->inter_sgl_boundary_mask)
            return -EIO;
    }

    /* Nice! Lets merge! */
    switch (merge_type)
    {
        case MERGE_FRONT:
            request_add_bio_head(req, bio);
            req->r_sector -= bio_sectors;
            break;
        case MERGE_BACK:
            request_add_bio_tail(req, bio);
            break;
    }

    req->r_nsectors += bio_sectors;

    return 0;
}

int block_attempt_merge(struct request *req, struct bio_req *bio, size_t bio_size)
{
    struct blockdev *bdev = req->r_bdev;
    DCHECK(bdev == bio->bdev);
    size_t bio_sectors = bio_size / 512;
    enum merge_type merge;

    /* Check if we can merge from the front or the back */
    if (bio->sector_number == req->r_sector - bio_sectors)
        merge = MERGE_FRONT;
    else if (bio->sector_number == req->r_sector + req->r_nsectors)
        merge = MERGE_BACK;
    else
    {
        DCHECK(false);
    }

    return block_do_merge(req, bio, bio_sectors, merge);
}

/**
 * @brief Check if it *may* be possible to merge with a request, without doing it
 *
 * @param req Request to check against
 * @param bio Bio to attempt to merge
 * @return True if possible, else false
 */
static bool block_may_merge(struct request *req, struct bio_req *bio, size_t bio_size)
{
    size_t bio_sectors = bio_size / 512;

    if (!(bio->sector_number == req->r_sector - bio_sectors) &&
        !(bio->sector_number == req->r_sector + req->r_nsectors))
        return false;

    if (req->r_bdev != bio->bdev)
        return false;

    if ((req->r_flags & BIO_REQ_OP_MASK) != (bio->flags & BIO_REQ_OP_MASK))
        return false;
    return true;
}

#define PLUG_ALL_CHECK_TOO_EXPENSIVE_CUTOFF 32

static size_t bio_calc_size(struct bio_req *bio)
{
    /* TODO: Calculate the size continuously in the bio when adding pages */
    size_t len = 0;
    for (size_t i = 0; i < bio->nr_vecs; i++)
        len += bio->vec[i].length;
    return len;
}

/**
 * @brief Attempt to merge a bio with a plug
 *
 * @param plug Plug to merge with
 * @param bio Bio to merge
 * @return If successful, return true, else false
 */
bool blk_merge_plug(struct blk_plug *plug, struct bio_req *bio)
{
    if (plug->nr_requests == 0)
        return false;

    size_t bio_size = bio_calc_size(bio);

    /* Try to merge with the plug. We improvise a random cutoff point to which we'll only check
     * against the head and the tail of the plug. */
    if (plug->nr_requests < PLUG_ALL_CHECK_TOO_EXPENSIVE_CUTOFF)
    {
        list_for_every (&plug->request_list)
        {
            struct request *req = list_head_to_request(l);
            if (block_may_merge(req, bio, bio_size) && !block_attempt_merge(req, bio, bio_size))
                return true;
        }
    }
    else
    {
        /* nr_requests is too large, check only the head and the tail */
        struct request *head = list_head_to_request(list_first_element(&plug->request_list));
        struct request *tail = list_head_to_request(list_last_element(&plug->request_list));

        if (head != tail && block_may_merge(head, bio, bio_size) &&
            !block_attempt_merge(head, bio, bio_size))
            return true;
        if (block_may_merge(tail, bio, bio_size) && !block_attempt_merge(tail, bio, bio_size))
            return true;
    }

    return false;
}

#ifdef CONFIG_KUNIT

static blockdev test_bdev;

void bio_push_many(struct bio_req *req)
{
}

template <typename... Args>
void bio_push_many(struct bio_req *req, struct page_iov iov, Args... args)
{
    bio_push_pages(req, iov.page, iov.page_off, iov.length);
    bio_push_many(req, args...);
}

template <size_t N>
static bool request_check_layout(struct request *req, sector_t expected_sector,
                                 const array<page_iov, N> &iovs)
{
    bool layout_correct = true;

    if (req->r_sector != expected_sector)
        return false;
    if (req->r_nr_sgls != iovs.size())
        return false;

    auto it = iovs.cbegin();

    for_every_bio(req, [&](struct bio_req *bio) {
        for (size_t i = 0; i < bio->nr_vecs; i++)
        {
            struct page_iov *vec = &bio->vec[i];

            if (it == iovs.cend())
            {
                layout_correct = false;
                break;
            }

            if (vec->page != it->page || vec->page_off != it->page_off || vec->length != it->length)
                layout_correct = false;
            ++it;
        }
    });

    return layout_correct;
}

TEST(request, merge_front_works)
{
    /* Check if front-merging works properly */
    struct page *test_page = vm_get_zero_page();
    struct bio_req *req0 = bio_alloc(GFP_KERNEL, 3);
    ASSERT_NONNULL(req0);
    struct bio_req *req1 = bio_alloc(GFP_KERNEL, 3);
    ASSERT_NONNULL(req1);

    const array<page_iov, 3> first_request_layout = {
        page_iov{test_page, PAGE_SIZE, 0},
        page_iov{test_page, 512, 0},
        page_iov{test_page, 1024, 512},
    };

    req0->bdev = req1->bdev = &test_bdev;

    /* Lets set up some bios with particular funny (valid!) layouts, so they're easily testable and
     * distinguishable later */
    bio_push_many(req0, page_iov{test_page, PAGE_SIZE, 0}, page_iov{test_page, 512, 0},
                  page_iov{test_page, 1024, 512});
    req0->sector_number = 10;
    bio_push_many(req1, page_iov{test_page, 512, 0}, page_iov{test_page, 512, 1024},
                  page_iov{test_page, 512, 512});
    req1->sector_number = 7;

    struct request *req = bio_req_to_request(req0);
    ASSERT_NONNULL(req);
    EXPECT_TRUE(request_check_layout(req, 10, first_request_layout));

    EXPECT_EQ(block_attempt_merge(req, req1, 512ul * 3), 0);

    const array<page_iov, 6> second_request_layout = {
        page_iov{test_page, 512, 0},   page_iov{test_page, 512, 1024},
        page_iov{test_page, 512, 512}, page_iov{test_page, PAGE_SIZE, 0},
        page_iov{test_page, 512, 0},   page_iov{test_page, 1024, 512},
    };

    EXPECT_TRUE(request_check_layout(req, 7, second_request_layout));

    block_request_free(req);
}

TEST(request, merge_back_works)
{
    struct page *test_page = vm_get_zero_page();
    struct bio_req *req0 = bio_alloc(GFP_KERNEL, 3);
    ASSERT_NONNULL(req0);
    struct bio_req *req1 = bio_alloc(GFP_KERNEL, 3);
    ASSERT_NONNULL(req1);

    const array<page_iov, 3> first_request_layout = {
        page_iov{test_page, 512, 0},
        page_iov{test_page, 512, 0},
        page_iov{test_page, 1024, 512},
    };

    req0->bdev = req1->bdev = &test_bdev;

    /* Lets set up some bios with particular funny (valid!) layouts, so they're easily testable and
     * distinguishable later */
    bio_push_many(req0, page_iov{test_page, 512, 0}, page_iov{test_page, 512, 0},
                  page_iov{test_page, 1024, 512});
    req0->sector_number = 10;
    bio_push_many(req1, page_iov{test_page, 512, 0}, page_iov{test_page, 512, 1024},
                  page_iov{test_page, 512, 512});
    req1->sector_number = 14;

    struct request *req = bio_req_to_request(req0);
    ASSERT_NONNULL(req);
    EXPECT_TRUE(request_check_layout(req, 10, first_request_layout));

    EXPECT_EQ(block_attempt_merge(req, req1, 512ul * 3), 0);

    const array<page_iov, 6> second_request_layout = {
        page_iov{test_page, 512, 0}, page_iov{test_page, 512, 0},    page_iov{test_page, 1024, 512},
        page_iov{test_page, 512, 0}, page_iov{test_page, 512, 1024}, page_iov{test_page, 512, 512},
    };

    EXPECT_TRUE(request_check_layout(req, 10, second_request_layout));

    block_request_free(req);
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

TEST(request, bad_nvme_merges_fail)
{
    /* Test if merges that would result in bad NVMe requests just outright fail, where the bios
     * themselves are well-formed. */
    struct blockdev nvmebdev;
    nvmebdev.bdev_queue_properties = nvme_queue_properties();

    struct page *test_page = vm_get_zero_page();
    struct bio_req *req0 = bio_alloc(GFP_KERNEL, 1);
    ASSERT_NONNULL(req0);
    struct bio_req *req1 = bio_alloc(GFP_KERNEL, 1);
    ASSERT_NONNULL(req1);

    req0->bdev = req1->bdev = &nvmebdev;

    bio_push_pages(req0, test_page, 512, 1024);
    bio_push_pages(req1, test_page, 512, PAGE_SIZE - 512);
    bio_reset_vec_index(req0);
    bio_reset_vec_index(req1);

    req0->sector_number = 10;
    req1->sector_number = 10 - (PAGE_SIZE / 512) + 1;

    /* Test front merges where the old head will be misaligned wrt inter_sgl_boundary_mask */
    struct request *req = bio_req_to_request(req0);
    ASSERT_NONNULL(req);
    EXPECT_NE(block_attempt_merge(req, req1, PAGE_SIZE - 512), 0);
    block_request_free(req);

    bio_push_pages(req0, test_page, 0, 1024);
    bio_push_pages(req1, test_page, 0, 1024);
    bio_reset_vec_index(req0);
    bio_reset_vec_index(req1);

    req0->sector_number = 10;
    req1->sector_number = 8;

    /* Test front merges where the new head's tail will be misaligned wrt inter_sgl_boundary_mask */
    req = bio_req_to_request(req0);
    ASSERT_NONNULL(req);
    EXPECT_NE(block_attempt_merge(req, req1, 1024ul), 0);
    block_request_free(req);

    bio_push_pages(req0, test_page, 0, 1024);
    bio_push_pages(req1, test_page, 0, 1024);
    bio_reset_vec_index(req0);
    bio_reset_vec_index(req1);

    req0->sector_number = 10;
    req1->sector_number = 12;

    /* Test back merges where the old tail will be misaligned wrt inter_sgl_boundary_mask */
    req = bio_req_to_request(req0);
    ASSERT_NONNULL(req);
    EXPECT_NE(block_attempt_merge(req, req1, 1024ul), 0);
    block_request_free(req);

    bio_push_pages(req0, test_page, 0, PAGE_SIZE);
    bio_push_pages(req1, test_page, 512, 1024);
    bio_reset_vec_index(req0);
    bio_reset_vec_index(req1);

    req0->sector_number = 10;
    req1->sector_number = 10 + (PAGE_SIZE / 512);

    /* Test back merges where the new bio's head will be misaligned wrt inter_sgl_boundary_mask */
    req = bio_req_to_request(req0);
    ASSERT_NONNULL(req);
    EXPECT_NE(block_attempt_merge(req, req1, 1024ul), 0);
    block_request_free(req);
}

#endif
