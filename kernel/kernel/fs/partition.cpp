/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <stdio.h>
#include <errno.h>
#include <stdbool.h>

#include <partitions.h>
#include <mbr.h>
#include <gpt.h>

#include <onyx/block.h>

static filesystem_mount_t *filesystems = NULL;

void insert_filesystem_mount(filesystem_mount_t *m)
{
	if(!filesystems)
	{
		filesystems = m;
	}
	else
	{
		filesystem_mount_t *mounts = filesystems;
		for(; mounts->next; mounts = mounts->next);

		mounts->next = m;
	}
}

filesystem_mount_t *find_filesystem_handler(const char *fsname)
{
	if(!filesystems)
		return NULL;
	for(filesystem_mount_t *m = filesystems; m; m = m->next)
	{
		if(!strcmp(m->filesystem, (char*) fsname))
			return m;
	}
	return NULL;
}

int partition_add_handler(fs_handler handler, const char *filesystem)
{	
	filesystem_mount_t *mount = (filesystem_mount_t *) zalloc(sizeof(filesystem_mount_t));
	if(!mount)
		return -1;
	mount->handler = handler;
	mount->filesystem = filesystem;

	/* Insert into the linked list */
	insert_filesystem_mount(mount);

	return 0;
}


int partition_setup(struct dev *dev, struct blockdev *block,
		    size_t first_sector, size_t last_sector)
{
	struct blockdev *d = (blockdev *) zalloc(sizeof(struct blockdev));
	if(!d)
		return -ENOMEM;
	
	d->dev = dev;
	d->offset = first_sector * block->sector_size;
	d->name = dev->name;
	d->sector_size = block->sector_size;
	d->nr_sectors = (last_sector - first_sector) + 1;
	d->actual_blockdev = block;
	d->submit_request = block->submit_request;
	d->device_info = block->device_info;

	if(blkdev_init(d) < 0)
	{
		free(d);
		return -1;
	}

	return 0;
}

static uuid_t unused_type = {0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000};

static struct page *read_disk(struct blockdev *dev, sector_t sector, size_t count)
{
	size_t nr_pages = vm_size_to_pages(count);
	struct page *p = nullptr;
	size_t c = 0;
	int st = 0;
	struct page *pages = alloc_pages(nr_pages, PAGE_ALLOC_NO_ZERO | PAGE_ALLOC_CONTIGUOUS);
	if(!pages)
		return NULL;
	
	struct page_iov *vec = (page_iov *) calloc(nr_pages, sizeof(struct page_iov));
	if(!vec)
	{
		st = -ENOMEM;
		goto out;
	}

	p = pages;
	c = count;

	for(unsigned int i = 0; i < nr_pages; i++)
	{
		vec[i].page = p;
		vec[i].length = min(c, PAGE_SIZE);
		vec[i].page_off = 0;
		p = p->next_un.next_allocation;
		c -= vec[i].length;
	}

	struct bio_req r;
	r.curr_vec_index = 0;
	r.flags = BIO_REQ_READ_OP;
	r.nr_vecs = nr_pages;
	r.sector_number = sector;
	r.vec = vec;

	st = bio_submit_request(dev, &r);
out:
	if(st < 0) free_pages(pages);
	free(vec);

	if(st < 0)
		errno = -st;

	return st < 0 ? NULL : pages;
}

int partition_setup_disk_gpt(struct blockdev *dev)
{
	int st = 0;
	gpt_partition_entry_t *part_table = NULL;
	struct page_iov *vec = NULL;
	size_t count = 0;
	struct page *p = nullptr;
	unsigned int nr_parts = 0;
	struct page *part_tab_pages = NULL;
	struct page *gpt_header_pages = read_disk(dev, 1, 512);
	if(!gpt_header_pages)
		return -errno;

	gpt_header_t *gpt_header = (gpt_header_t *) PAGE_TO_VIRT(gpt_header_pages);

	/* TODO: Verify the CRC32 checksum */
	if(memcmp(gpt_header->signature, GPT_SIGNATURE, 8))
	{
		st = -ENOENT;
		goto out;
	}

	count = ALIGN_TO(gpt_header->num_partitions * gpt_header->part_entry_len, dev->sector_size);
	part_tab_pages = alloc_pages(vm_size_to_pages(count), PAGE_ALLOC_NO_ZERO | PAGE_ALLOC_CONTIGUOUS);
	if(!part_tab_pages)
	{
		st = -ENOMEM;
		goto out;
	}

	part_table = (gpt_partition_entry_t *) PAGE_TO_VIRT(part_tab_pages);

	vec = (page_iov *) calloc(vm_size_to_pages(count), sizeof(struct page_iov));
	if(!vec)
	{
		st = -ENOMEM;
		goto out;
	}

	p = part_tab_pages;

	for(unsigned int i = 0; i < vm_size_to_pages(count); i++)
	{
		vec[i].page = p;
		vec[i].length = PAGE_SIZE;
		vec[i].page_off = 0;
		p = p->next_un.next_allocation;
	}

	struct bio_req r;
	r.curr_vec_index = 0;
	r.flags = BIO_REQ_READ_OP;
	r.nr_vecs = vm_size_to_pages(count);
	r.sector_number = 2;
	r.vec = vec;

	if(bio_submit_request(dev, &r) < 0)
	{
		printk("Error reading partition table\n");
		st = -EIO;
		goto out;
	}

	/* FIXME: Support actually reading partition entries */
	for(uint32_t i = 0; i < gpt_header->num_partitions; i++)
	{
		gpt_partition_entry_t *e = &part_table[i];
		
		if(!memcmp(e->partition_type, unused_type, sizeof(uuid_t)))
			continue;
		char nr = '1' + nr_parts;

		/* FIXME: Support partition numbers > 9 */
		if(nr_parts + 1 > 9)
		{
			st = -E2BIG;
			goto out;
		}

		size_t name_len = strlen(dev->name);
		char *name = (char *) malloc(name_len + 2);
		if(!name)
		{
			st = -ENOMEM;
			goto out;
		}
	
		strcpy(name, dev->name);
		name[name_len] = nr;
		name[name_len + 1] = '\0';

		struct dev *d = dev_register(MAJOR(dev->dev->majorminor), nr_parts + 1, name);
		if(!d)
		{
			free(name);
			st = -errno;
			goto out;
		}

		if(partition_setup(d, dev, e->first_lba, e->last_lba) < 0)
		{
			st = -errno;
			dev_unregister(d->majorminor);
			goto out;
		}

		//printk("registered! lba %lu\n", e->first_lba);
		nr_parts++;
	}

out:
	free_pages(gpt_header_pages);
	if(part_tab_pages) free_pages(part_tab_pages);
	free(vec);
	return st;
}

int partition_setup_disk_mbr(struct blockdev *dev)
{
	int st = 0;
	struct page *mbr_pages = read_disk(dev, 0, 512);
	if(!mbr_pages)
		return -errno;

	char *mbrbuf = (char *) PAGE_TO_VIRT(mbr_pages);
	
	mbrpart_t *part = (mbrpart_t*) ((char *) mbrbuf + 0x1BE);
	
	unsigned int nr_parts = 0;
	/* Cycle through all the partitions */
	for(int i = 0; i < 4; i++)
	{
		if(part->part_type != 0)
		{
			char nr = '1' + nr_parts;

			/* FIXME: Support partition numbers > 9 */
			if(nr_parts + 1 > 9)
			{
				st = -E2BIG;
				goto out;
			}

			size_t name_len = strlen(dev->name);
			char *name = (char *) malloc(name_len + 2);
			if(!name)
			{
				st = -ENOMEM;
				goto out;
			}
		
			strcpy(name, dev->name);
			name[name_len] = nr;
			name[name_len + 1] = '\0';

			struct dev *d = dev_register(MAJOR(dev->dev->majorminor), nr_parts + 1, name);
			if(!d)
			{
				free(name);
				st = -errno;
				goto out;
			}

			if(partition_setup(d, dev, part->sector, part->sector + part->size_sector) < 0)
			{
				st = -errno;
				dev_unregister(d->majorminor);
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
	if(partition_setup_disk_gpt(dev) < 0)
		partition_setup_disk_mbr(dev);
}
