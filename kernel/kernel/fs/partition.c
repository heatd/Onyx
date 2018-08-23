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

static volatile fs_handler mbr_code_handlers[0xFF];
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

int partition_add_handler(fs_handler handler, char *filesystem, uint8_t mbr_part_code, uuid_t *uuids, size_t num_uuids)
{
	mbr_code_handlers[mbr_part_code] = handler;
	
	filesystem_mount_t *mount = malloc(sizeof(filesystem_mount_t));
	if(!mount)
		return 1;
	mount->handler = handler;
	mount->filesystem = filesystem;
	mount->mbr_part_code = mbr_part_code;
	mount->uuids = uuids;
	mount->uuids_len = num_uuids;

	/* Insert into the linked list */
	insert_filesystem_mount(mount);

	return 0;
}

fs_handler lookup_handler_from_partition_code(enum partition_type_t type, uint8_t part_code)
{
	if(type == PARTITION_TYPE_MBR)
		return mbr_code_handlers[part_code];
	return NULL;
}

uint64_t partition_find_gpt(int index, block_device_t *dev, filesystem_mount_t *fs)
{
	gpt_header_t *gpt_header = malloc(512);
	if(!gpt_header)
		return errno = ENOMEM, 0;

	ssize_t read = blkdev_read(512, 512, gpt_header, dev);
	if(read != 512)
		return 0;

	/* TODO: Verify the CRC32 checksum */
	if(memcmp(gpt_header->signature, GPT_SIGNATURE, 8))
		return 0;

	size_t count = gpt_header->num_partitions * gpt_header->part_entry_len;
	gpt_partition_entry_t *part_table = malloc(count);
	if(!part_table)
	{
		free(gpt_header);
		return 0;
	}
	blkdev_read(1024, count, part_table, dev);
	for(uint32_t i = 0; i < gpt_header->num_partitions; i++)
	{
		if(i == (unsigned int) index)
		{
			bool is_correct = false;
			for(size_t j = 0; j < fs->uuids_len; j++)
			{
				if(!memcmp(part_table[i].partition_type, fs->uuids[j], 16))
				{
					is_correct = true;
					break;
				}
			}
			if(is_correct == false)
				return errno = EINVAL, 0;
			return part_table[i].first_lba;
		}
	}
	return errno = EINVAL, 0;
}

uint64_t partition_find(int index, block_device_t *dev, filesystem_mount_t *fs)
{
	/* Firstly, try to use GPT */
	uint64_t lba = 0;
	if((lba = partition_find_gpt(index, dev, fs)) != 0)
		return lba;
	/* Map the buffer */
	unsigned int *mbrbuf = malloc(512);
	if(!dev)
		return errno = ENOMEM, 0;
	memset(mbrbuf, 0, 512);
	/* Read the mbr from the disk */
	blkdev_read(0, 512, mbrbuf, dev);
	mbrpart_t *part = (mbrpart_t*)((char *)mbrbuf + 0x1BE);
	/* Cycle through all the partitions */
	for(int i = 0; i < 4; i++)
	{
		if(part->part_type != 0 && index == i)
		{
			if(part->part_type != fs->mbr_part_code)
				return 0;
		 	return part->sector;
		}
		part++;
	}
	return 0;
}