/*----------------------------------------------------------------------
 * Copyright (C) 2016 Pedro Falcato
 *
 * This file is part of Spartix, and is made available under
 * the terms of the GNU General Public License version 2.
 *
 * You can redistribute it and/or modify it under the terms of the GNU
 * General Public License version 2 as published by the Free Software
 * Foundation.
 *----------------------------------------------------------------------*/
#ifndef _EXT2_H
#define _EXT2_H

#include <stdint.h>
#include <drivers/ata.h>

#define EXT2_MBR_CODE 0x83
#define EXT2_FS_CLEAN 1
#define EXT2_FS_ERROR 2
#define EXT2_IGNORE_ERROR 1
#define EXT2_REMOUNT_RO 2
#define EXT2_KPANIC 3
#define EXT2_LINUX_ID 0
#define EXT2_GNU_HURD_ID 1
#define EXT2_MASIX_ID 2
#define EXT2_FREEBSD_ID 3
#define EXT2_BSD 4
#define EXT2_OPT_PREALLOCATE_CONTIGUOUS_BLOCKS 1
#define EXT2_OPT_AFS_SERVER_IND_EXIST 2
#define EXT2_OPT_FS_JOURNAL 4
#define EXT2_OPT_INODES_EXTENDED_ATTRB 8
#define EXT2_OPT_RESIZE_LARGER_PARTITIONS 0x10
#define EXT2_OPT_DIRECTORIES_USE_HASH_INDEX 0x20
#define EXT2_RQRD_COMPRESSION_USED 1
#define EXT2_RQRD_DIR_ENTRIES_TYPE_FIELD 2
#define EXT2_RQRD_FS_REPLAY_JOURNAL 4
#define EXT2_RQRD_FS_JOURNAL_DEVICE 8
#define EXT2_ROFTR_SPARSE_SUPERBLOCKS_GROUP_DESC_TABLES 1
#define EXT2_ROFTR_FS_64BIT_SZ 2
#define EXT2_ROFTR_DIR_CONTENTS_BIN_TREE 4
typedef struct
{
	uint32_t first_non_reserved_inode;
	uint16_t size_inode_bytes;
	uint16_t block_group;
	uint32_t optional_features;
	uint32_t required_features;
	uint32_t features_ifnot_ro;
	uint64_t fs_id[2];
	uint8_t last_path[64];
	uint32_t compression_algorithms;
	uint8_t prealloc_blocks_for_files;
	uint8_t prealloc_blocks_for_dirs;
	uint16_t unused;
	uint64_t journal_id[2];
	uint32_t journal_inode;
	uint32_t journal_device;
	uint32_t head_orphan_inode_list;
} extsuperblock_t;
typedef struct
{
	uint32_t total_inodes;
	uint32_t total_blocks;
	uint32_t su_blocks;
	uint32_t unallocated_block;
	uint32_t unallocated_inodes;
	uint32_t sb_number;
	uint32_t log2blocksz;
	uint32_t log2fragsz;
	uint32_t blockgroupblocks;
	uint32_t blockgroupfrags;
	uint32_t blockgroupinodes;
	uint32_t lastmountposix;
	uint32_t lastwriteposix;
	uint16_t times_mounted_after_fsck;
	uint16_t mounts_allowed_before_fsck;
	uint16_t ext2sig;
	uint16_t fs_state;
	uint16_t error_detected_action;
	uint16_t minor_version;
	uint32_t lastfsckposix;
	uint32_t interval_forced_fsck;
	uint32_t os_id_created;
	uint32_t major_version;
	uint16_t uid_reserved_blocks;
	uint16_t gid_reserved_blocks;
	extsuperblock_t ext;
} __attribute__((aligned(1024))) superblock_t;
typedef struct
{
	uint32_t major;
	uint32_t minor;
} ext2_version_t;
void init_ext2drv();
#endif
