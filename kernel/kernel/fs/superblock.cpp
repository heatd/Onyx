/*
 * Copyright (c) 2017 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 */
#include <onyx/block.h>
#include <onyx/superblock.h>
#include <onyx/vfs.h>

void superblock_init(struct superblock *sb)
{
    INIT_LIST_HEAD(&sb->s_inodes);
    sb->s_ref = 1;
    spinlock_init(&sb->s_ilock);
    sb->s_flags = 0;
}

int sb_read_bio(struct superblock *sb, struct page_iov *vec, size_t nr_vecs, size_t block_number)
{
    struct bio_req r
    {
    };
    r.nr_vecs = nr_vecs;
    r.vec = vec;
    r.sector_number = block_number * (sb->s_block_size / sb->s_bdev->sector_size);
    r.flags = BIO_REQ_READ_OP;

    return bio_submit_request(sb->s_bdev, &r);
}

int sb_write_bio(struct superblock *sb, struct page_iov *vec, size_t nr_vecs, size_t block_number)
{
    struct bio_req r
    {
    };
    r.nr_vecs = nr_vecs;
    r.vec = vec;
    r.sector_number = block_number * (sb->s_block_size / sb->s_bdev->sector_size);
    r.flags = BIO_REQ_WRITE_OP;

    return bio_submit_request(sb->s_bdev, &r);
}
