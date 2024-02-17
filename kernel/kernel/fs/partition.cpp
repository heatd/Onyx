/*
 * Copyright (c) 2016 - 2024 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>

#include <onyx/bio.h>
#include <onyx/crc32.h>
#include <onyx/fs_mount.h>
#include <onyx/gpt.h>
#include <onyx/log.h>
#include <onyx/mbr.h>

static list_head fs_mount_list = LIST_HEAD_INIT(fs_mount_list);
static spinlock fs_mount_list_lock;

/**
 * @brief Add a fs mount object to the kernel's registry
 * After this call, mount(2) can try and mount these types of filesystems
 *
 * @param handler Callback to the mount handler
 * @param flags Flags (see FS_MOUNT_*)
 * @param name Name of the filesystem, passed by mount(2)
 * @return 0 on success, else negative error codes
 */
int fs_mount_add(fs_sb_mount handler, unsigned int flags, cul::string name)
{
    scoped_lock g{fs_mount_list_lock};
    auto mount = make_unique<fs_mount>();

    if (!mount)
        return -ENOMEM;

    mount->mount = handler;
    mount->flags = flags;
    mount->name = cul::move(name);

    list_add_tail(&mount->list_node, &fs_mount_list);

    mount.release();
    return 0;
}

/**
 * @brief Find the fs_mount from the name
 *
 * @param fsname Name of the filesystem, passed by mount(2)
 * @return Pointer to the fs_mount, or NULL
 */
fs_mount *fs_mount_get(const char *fsname)
{
    scoped_lock g{fs_mount_list_lock};

    list_for_every (&fs_mount_list)
    {
        auto mount = container_of(l, fs_mount, list_node);

        if (mount->name == fsname)
            return mount;
    }

    return nullptr;
}

static int partition_setup(cul::string &&name, struct blockdev *block, size_t first_sector,
                           size_t last_sector)
{
    blockdev *d = new blockdev;
    if (!d)
        return -ENOMEM;

    d->offset = first_sector * block->sector_size;
    d->name = cul::move(name);
    d->sector_size = block->sector_size;
    d->nr_sectors = (last_sector - first_sector) + 1;
    d->actual_blockdev = block;
    d->submit_request = block->submit_request;
    d->device_info = block->device_info;

    if (int st = blkdev_init(d); st < 0)
    {
        delete d;
        return st;
    }

    return 0;
}

static uuid_t unused_type = {0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000};

static expected<struct page *, int> read_disk(struct blockdev *dev, sector_t sector, size_t count)
{
    size_t nr_pages = vm_size_to_pages(count);
    struct bio_req *r = nullptr;
    struct page *p = nullptr;
    int st = 0;
    struct page *pages =
        alloc_pages(pages2order(nr_pages), PAGE_ALLOC_NO_ZERO | PAGE_ALLOC_CONTIGUOUS);
    if (!pages)
        return unexpected{-ENOMEM};

    p = pages;

    r = bio_alloc(GFP_KERNEL, nr_pages);
    if (!r)
    {
        st = -ENOMEM;
        goto out;
    }

    r->curr_vec_index = 0;
    r->flags = BIO_REQ_READ_OP;
    r->sector_number = sector;

    for (unsigned int i = 0; i < nr_pages; i++)
    {
        r->vec[i].page = p;
        r->vec[i].length = PAGE_SIZE;
        r->vec[i].page_off = 0;
        p = p->next_un.next_allocation;
    }

    st = bio_submit_req_wait(dev, r);
    bio_put(r);
out:
    if (st < 0)
        free_pages(pages);

    if (st < 0)
        return unexpected{st};

    return pages;
}

/**
 * @brief Add a partition to a block device
 *
 * @param dev Pointer to the blockdev
 * @param nr_partition Number of the partition
 * @param first_lba First LBA
 * @param last_lba Last LBA
 * @return Negative error code or 0 for success
 */
int partition_add(blockdev *dev, int nr_partition, uint64_t first_lba, uint64_t last_lba)
{
    // Arbitrary length but should be safe because of snprintf
    char partition_num[20];
    if (snprintf(partition_num, sizeof(partition_num), "%s%d", dev->partition_prefix.c_str(),
                 nr_partition) >= (int) sizeof(partition_num))
        return -EINVAL;

    cul::string name = dev->name;
    if (!name)
        return -ENOMEM;

    // Append the partition number
    if (!name.append(std::string_view{partition_num, strlen(partition_num)}))
        return -ENOMEM;

    if (int st = partition_setup(cul::move(name), dev, first_lba, last_lba); st < 0)
        return st;

    return 0;
}

int partition_setup_disk_gpt(struct blockdev *dev)
{
    int st = 0;
    gpt_partition_entry_t *part_table = nullptr;
    size_t count = 0;
    struct page *p = nullptr;
    unsigned int nr_parts = 1;
    struct page *part_tab_pages = nullptr;
    struct bio_req *r = nullptr;
    size_t nr_pages = 0;

    auto ex = read_disk(dev, 1, dev->sector_size);
    if (ex.has_error())
        return ex.error();

    struct page *gpt_header_pages = ex.value();
    gpt_header_t *gpt_header = (gpt_header_t *) PAGE_TO_VIRT(gpt_header_pages);
    auto csum = gpt_header->crc32_checksum;
    uint32_t actual_csum = 0;

    if (memcmp(gpt_header->signature, GPT_SIGNATURE, 8))
    {
        st = -ENOENT;
        goto out;
    }

    gpt_header->crc32_checksum = 0;

    if (gpt_header->header_size > dev->sector_size)
    {
        ERROR("gpt", "disk %s has invalid GPT table (bad header size\n", dev->name.c_str());
        st = -EINVAL;
        goto out;
    }

    actual_csum = crc32_calculate((uint8_t *) gpt_header, gpt_header->header_size);
    if (le32toh(csum) != actual_csum)
    {
        ERROR("gpt", "disk %s has wrong GPT header checksum\n", dev->name.c_str());
        st = -EINVAL;
        goto out;
    }

    count = ALIGN_TO(gpt_header->num_partitions * gpt_header->part_entry_len, dev->sector_size);
    nr_pages = vm_size_to_pages(count);
    part_tab_pages = alloc_pages(pages2order(nr_pages), PAGE_ALLOC_NO_ZERO | PAGE_ALLOC_CONTIGUOUS);
    if (!part_tab_pages)
    {
        st = -ENOMEM;
        goto out;
    }

    part_table = (gpt_partition_entry_t *) PAGE_TO_VIRT(part_tab_pages);

    p = part_tab_pages;

    r = bio_alloc(GFP_KERNEL, nr_pages);
    if (!r)
    {
        st = -ENOMEM;
        goto out;
    }

    r->curr_vec_index = 0;
    r->flags = BIO_REQ_READ_OP;
    r->sector_number = 2;

    for (unsigned int i = 0; i < vm_size_to_pages(count); i++)
    {
        r->vec[i].page = p;
        r->vec[i].length = PAGE_SIZE;
        r->vec[i].page_off = 0;
        p = p->next_un.next_allocation;
    }

    if (bio_submit_req_wait(dev, r) < 0)
    {
        bio_put(r);
        printk("Error reading partition table\n");
        st = -EIO;
        goto out;
    }

    bio_put(r);

    csum = gpt_header->partition_array_crc32;
    actual_csum = crc32_calculate((uint8_t *) part_table, count);

    if (le32toh(csum) != actual_csum)
    {
        ERROR("gpt", "disk %s has wrong GPT partition table checksum\n", dev->name.c_str());
        st = -EINVAL;
        goto out;
    }

    for (uint32_t i = 0; i < gpt_header->num_partitions; i++)
    {
        gpt_partition_entry_t *e = &part_table[i];

        if (!memcmp(e->partition_type, unused_type, sizeof(uuid_t)))
            continue;

        if ((st = partition_add(dev, nr_parts, e->first_lba, e->last_lba)) < 0)
        {
            goto out;
        }

        nr_parts++;
    }

out:
    free_pages(gpt_header_pages);
    if (part_tab_pages)
        free_pages(part_tab_pages);
    return st;
}

int partition_setup_disk_mbr(struct blockdev *dev)
{
    int st = 0;
    auto ex = read_disk(dev, 0, 512);
    if (ex.has_error())
        return ex.error();

    struct page *mbr_pages = ex.value();
    char *mbrbuf = (char *) PAGE_TO_VIRT(mbr_pages);
    mbrpart_t *part = (mbrpart_t *) ((char *) mbrbuf + 0x1BE);
    unsigned int nr_parts = 1;

    /* Cycle through all the partitions */
    for (int i = 0; i < 4; i++)
    {
        if (part->part_type != 0)
        {
            if ((st = partition_add(dev, nr_parts, part->sector,
                                    part->sector + part->size_sector - 1)) < 0)
            {
                goto out;
            }

            nr_parts++;
        }

        part++;
    }
out:
    free_pages(mbr_pages);
    return st;
}

void partition_setup_disk(struct blockdev *dev)
{
    if (partition_setup_disk_gpt(dev) < 0)
        partition_setup_disk_mbr(dev);
}
