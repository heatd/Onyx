/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _PARTITIONS_H
#define _PARTITIONS_H

#include <stdint.h>

#include <sys/types.h>

#include <kernel/block.h>
#include <kernel/vfs.h>
typedef struct inode *(*fs_handler)(uint64_t sector, block_device_t *dev);
enum partition_type_t
{
	PARTITION_TYPE_MBR,
	PARTITION_TYPE_GPT
};
typedef struct fs_mount_strct
{
	struct fs_mount_strct *next;
	char *filesystem;
	uuid_t *uuids;
	size_t uuids_len;
	uint8_t mbr_part_code;
	fs_handler handler;
} filesystem_mount_t;

#ifdef __cplusplus
extern "C"{
#endif

int partition_add_handler(fs_handler handler, char *filesystem, uint8_t mbr_part_code, uuid_t *uuids, size_t num_uuids);
uint64_t partition_find(int index, block_device_t *dev, filesystem_mount_t *fs);
filesystem_mount_t *find_filesystem_handler(const char *fsname);
fs_handler lookup_handler_from_partition_code(enum partition_type_t type, uint8_t part_code);

#ifdef __cplusplus
}
#endif

#endif
