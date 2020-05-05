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

int partition_add_handler(fs_handler handler, char *filesystem)
{	
	filesystem_mount_t *mount = zalloc(sizeof(filesystem_mount_t));
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
	struct blockdev *d = zalloc(sizeof(struct blockdev));
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

int partition_setup_disk_gpt(struct blockdev *dev)
{
	int st = 0;
	gpt_partition_entry_t *part_table = NULL;
	gpt_header_t *gpt_header = malloc(512);
	if(!gpt_header)
		return errno = ENOMEM, 0;

	ssize_t read = blkdev_read(512, 512, gpt_header, dev);
	if(read != 512)
	{
		st = -ENXIO;
		goto out;
	}

	/* TODO: Verify the CRC32 checksum */
	if(memcmp(gpt_header->signature, GPT_SIGNATURE, 8))
	{
		st = -ENOENT;
		goto out;
	}

	size_t count = gpt_header->num_partitions * gpt_header->part_entry_len;
	part_table = malloc(count);
	if(!part_table)
	{
		st = -ENOMEM;
		goto out;
	}

	unsigned int nr_parts = 0;

	blkdev_read(1024, count, part_table, dev);
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
		char *name = malloc(name_len + 2);
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

		nr_parts++;
	}

out:
	free(gpt_header);
	free(part_table);
	return st;
}

int partition_setup_disk_mbr(struct blockdev *dev)
{
	int st = 0;
	char *mbrbuf = malloc(512);
	if(!mbrbuf)
		return -ENOMEM;

	/* Read the mbr from the disk */
	blkdev_read(0, 512, mbrbuf, dev);
	
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
			char *name = malloc(name_len + 2);
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
	free(mbrbuf);
	return st;
}

void partition_setup_disk(struct blockdev *dev)
{
	if(partition_setup_disk_gpt(dev) < 0)
		partition_setup_disk_mbr(dev);
}
