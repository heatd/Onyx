/*
 * Copyright (c) 2017 - 2024 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <onyx/block.h>
#include <onyx/dentry.h>
#include <onyx/superblock.h>
#include <onyx/vfs.h>

static int sb_scan_objects(struct shrinker *s, struct shrink_control *ctl);
static int sb_shrink_objects(struct shrinker *s, struct shrink_control *ctl);

void superblock_init(struct superblock *sb)
{
    INIT_LIST_HEAD(&sb->s_inodes);
    sb->s_ref = 1;
    spinlock_init(&sb->s_ilock);
    sb->s_flags = 0;
    mutex_init(&sb->s_rename_lock);
    lru_list_init(&sb->s_dcache_lru);
    sb->s_shrinker.name = "superblock";
    sb->s_shrinker.flags = SHRINKER_NEEDS_IO;
    sb->s_shrinker.scan_objects = sb_scan_objects;
    sb->s_shrinker.shrink_objects = sb_shrink_objects;

    shrinker_register(&sb->s_shrinker);
}

int sb_read_bio(struct superblock *sb, struct page_iov *vec, size_t nr_vecs, size_t block_number)
{
    struct bio_req *r = bio_alloc(GFP_NOFS, nr_vecs);
    if (!r)
        return -ENOMEM;

    r->sector_number = block_number * (sb->s_block_size / sb->s_bdev->sector_size);
    r->flags = BIO_REQ_READ_OP;
    memcpy(r->vec, vec, nr_vecs * sizeof(struct page_iov));

    int st = bio_submit_req_wait(sb->s_bdev, r);
    bio_put(r);
    return st;
}

int sb_write_bio(struct superblock *sb, struct page_iov *vec, size_t nr_vecs, size_t block_number,
                 void (*endio)(struct bio_req *), void *b_private)
{
    struct bio_req *r = bio_alloc(GFP_NOFS, nr_vecs);
    if (!r)
        return -ENOMEM;

    r->b_end_io = endio;
    r->sector_number = block_number * (sb->s_block_size / sb->s_bdev->sector_size);
    r->flags = BIO_REQ_WRITE_OP;
    r->b_private = b_private;
    memcpy(r->vec, vec, nr_vecs * sizeof(struct page_iov));

    int st = bio_submit_request(sb->s_bdev, r);
    bio_put(r);
    return st;
}

#define shrinker_to_sb(s) container_of(s, struct superblock, s_shrinker)

static int sb_scan_objects(struct shrinker *s, struct shrink_control *ctl)
{
    struct superblock *sb = shrinker_to_sb(s);
    struct dcache_scan_result res = {};
    lru_list_walk(&sb->s_dcache_lru, scan_dcache_lru_one, &res);
    ctl->target_objs = res.scanned_bytes;
    return 0;
}

struct shrink_data
{
    struct list_head shrink_list;
};

void shrink_list(struct shrink_data *s);

static int sb_shrink_objects(struct shrinker *s, struct shrink_control *ctl)
{
    struct superblock *sb = shrinker_to_sb(s);
    struct dcache_shrink_result res = {0, ctl->target_objs};
    INIT_LIST_HEAD(&res.reclaim_list);
    lru_list_walk(&sb->s_dcache_lru, shrink_dcache_lru_one, &res);
    ctl->nr_freed = ctl->target_objs - res.to_shrink_objs;
    struct shrink_data sdata;
    INIT_LIST_HEAD(&sdata.shrink_list);
    list_move(&sdata.shrink_list, &res.reclaim_list);
    shrink_list(&sdata);
    return 0;
}
