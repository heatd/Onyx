/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _EXT2_H
#define _EXT2_H

#include <stdint.h>

#include <onyx/mutex.h>
#include <onyx/spinlock.h>
#include <onyx/block.h>
#include <onyx/vfs.h>

#define EXT2_SUPERBLOCK_OFFSET		1024
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

#define EXT2_INO_TYPE_FIFO 0x1000
#define EXT2_INO_TYPE_CHARDEV 0x2000
#define EXT2_INO_TYPE_DIR 0x4000
#define EXT2_INO_TYPE_BLOCKDEV 0x6000
#define EXT2_INO_TYPE_REGFILE 0x8000
#define EXT2_INO_TYPE_SYMLINK 0xA000
#define EXT2_INO_TYPE_UNIX_SOCK 0xC000

#define EXT2_INO_FLAG_SECURE_DEL 0x1
#define EXT2_INO_FLAG_COPYDATA_DEL 0x2
#define EXT2_INO_FLAG_FILE_COMPRESS 0x4
#define EXT2_INO_FLAG_SYNCHRONOUS_UPDATES 0x8
#define EXT2_INO_FLAG_IMMUTABLE 0x10
#define EXT2_INO_FLAG_APPEND_ONLY 0x20
#define EXT2_INO_FLAG_NO_DUMP 0x40
#define EXT2_INO_FLAG_ATIME_NO_UPDT 0x80
#define EXT2_INO_FLAG_HASH_INDEXED_DIR 0x10000
#define EXT2_INO_FLAG_AFS_DIR 0x20000
#define EXT2_INO_FLAG_JOURNAL_FILE_DATA 0x40000

#define EXT2_FT_UNKNOWN			0
#define EXT2_FT_REG_FILE		1
#define EXT2_FT_DIR			2
#define EXT2_FT_CHRDEV			3
#define EXT2_FT_BLKDEV			4
#define EXT2_FT_FIFO			5
#define EXT2_FT_SOCK			6
#define EXT2_FT_SYMLINK			7

typedef struct
{
	uint32_t total_inodes;
	uint32_t total_blocks;
	uint32_t su_blocks;
	uint32_t unallocated_blocks;
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
	uint32_t first_non_reserved_inode;
	uint16_t size_inode_bytes;
	uint16_t block_group;
	uint32_t optional_features;
	uint32_t required_features;
	uint32_t features_ifnot_ro;
	uint64_t fs_id[2];
	uint64_t volume_name[2];
	uint8_t last_path[64];
	uint32_t compression_algorithms;
	uint8_t prealloc_blocks_for_files;
	uint8_t prealloc_blocks_for_dirs;
	uint16_t unused;
	uint64_t journal_id[2];
	uint32_t journal_inode;
	uint32_t journal_device;
	uint32_t head_orphan_inode_list;
} __attribute__((aligned(1024))) superblock_t;

typedef struct
{
	uint32_t block_usage_addr;
	uint32_t inode_usage_addr;
	uint32_t inode_table_addr;
	uint16_t unallocated_blocks_in_group;
	uint16_t unallocated_inodes_in_group;
	uint16_t used_dirs_count;
} __attribute__((aligned(32))) block_group_desc_t;

struct ext2_inode
{
	uint16_t mode;
	uint16_t uid;
	uint32_t size_lo;
	uint32_t atime;
	uint32_t ctime;
	uint32_t mtime;
	uint32_t dtime;
	uint16_t gid;
	uint16_t hard_links;
	uint32_t i_blocks;
	uint32_t flags;
	uint32_t os_spec;
	uint32_t dbp[12];
	uint32_t single_indirect_bp;
	uint32_t doubly_indirect_bp;
	uint32_t trebly_indirect_bp;
	uint32_t gen_number;
	uint32_t file_acl;
	uint32_t size_hi;
	uint32_t block_address_frag;
	uint32_t os_spec_val[3];
};

typedef struct
{
	uint32_t inode;
	uint16_t size;
	uint8_t lsbit_namelen;
	uint8_t type_indic;
	char name[255];
} dir_entry_t;

typedef struct ex
{
	superblock_t *sb;
	uint32_t major;
	uint32_t minor;
	uint32_t total_inodes;
	uint32_t total_blocks;
	uint32_t block_size;
	uint32_t frag_size;
	uint32_t blocks_per_block_group;
	uint32_t inodes_per_block_group;
	uint32_t number_of_block_groups;
	struct blockdev *blkdevice;
	uint16_t inode_size;
	block_group_desc_t *bgdt;
	struct spinlock sb_lock;
	struct mutex bgdt_lock;
	struct mutex ino_alloc_lock;
	void *zero_block; /* A pointer to a zero'd block of memory with size 'block_size' */
	unsigned int entry_shift;
	struct ex *next;
} ext2_fs_t;

struct ext2_inode_info
{
	/* Cached copy of the on-disk inode */
	struct ext2_inode *inode;
};

static inline struct ext2_inode *ext2_get_inode_from_node(struct inode *ino)
{
	assert(ino->i_helper != NULL);
	return ((struct ext2_inode_info *) ino->i_helper)->inode;
}

#define EXT2_TYPE_DIRECT_BLOCK		0
#define EXT2_TYPE_SINGLY_BLOCK		1
#define EXT2_TYPE_DOUBLY_BLOCK		2
#define EXT2_TYPE_TREBLY_BLOCK		3

#define EXT2_DIRECT_BLOCK_COUNT		12	

#define EXT2_ERR_INV_BLOCK		0

#define EXT2_GET_FILE_TYPE(mode) (mode & 0xE000)
#define EXT2_CALCULATE_SIZE64(ino) (((uint64_t)ino->size_hi << 32) | ino->size_lo)

extern const unsigned int direct_block_count;

void *ext2_read_block(uint32_t block_index, uint16_t blocks, ext2_fs_t *fs);
void ext2_read_block_raw(uint32_t block_index, uint16_t blocks, ext2_fs_t *fs,
	void *buffer);
void ext2_write_block(uint32_t block_index, uint16_t blocks, ext2_fs_t *fs,
	void *buffer);
uint32_t ext2_allocate_block(ext2_fs_t *fs);
void ext2_free_block(uint32_t block, ext2_fs_t *fs);
ssize_t ext2_read_inode(struct ext2_inode *ino, ext2_fs_t *fs,
	size_t size, off_t off, char *buffer);
ssize_t ext2_write_inode(struct ext2_inode *ino, ext2_fs_t *fs,
	size_t size, off_t off, char *buffer);
struct ext2_inode *ext2_allocate_inode(uint32_t *inode_number, ext2_fs_t *fs);
struct ext2_inode *ext2_get_inode_from_number(ext2_fs_t *fs, uint32_t inode);
uint32_t ext2_allocate_from_block_group(ext2_fs_t *fs, uint32_t block_group);
struct ext2_inode *ext2_allocate_inode_from_block_group(uint32_t *inode_no,
	uint32_t block_group, ext2_fs_t *fs);
void ext2_register_superblock_changes(ext2_fs_t *fs);
void ext2_register_bgdt_changes(ext2_fs_t *fs);
unsigned int ext2_detect_block_type(uint32_t block, ext2_fs_t *fs);
int ext2_add_block_to_inode(struct ext2_inode *inode, uint32_t block,
	uint32_t block_index, ext2_fs_t *fs);
void ext2_set_inode_size(struct ext2_inode *inode, size_t size);
void ext2_update_inode(struct ext2_inode *ino, ext2_fs_t *fs, uint32_t inode);
char *ext2_read_symlink(struct ext2_inode *ino, ext2_fs_t *fs);
struct ext2_inode *ext2_traverse_fs(struct ext2_inode *wd, const char *path, ext2_fs_t *fs,
	char **symlink_name, uint32_t *inode_num);
struct ext2_inode *ext2_get_inode_from_dir(ext2_fs_t *fs, dir_entry_t *dirent,
	char *name, uint32_t *inode_number, size_t size);
int ext2_add_direntry(const char *name, uint32_t inum, struct ext2_inode *inode,
	struct ext2_inode *dir, ext2_fs_t *fs);
int ext2_remove_direntry(uint32_t inum, struct ext2_inode *dir, ext2_fs_t *fs);

void ext2_free_inode(uint32_t inode, ext2_fs_t *fs);
void ext2_update_inode(struct ext2_inode *ino, ext2_fs_t *fs, uint32_t inode);
int ext2_ino_type_to_vfs_type(uint16_t mode);
uint16_t ext2_mode_to_ino_type(mode_t mode);
struct inode *ext2_fs_ino_to_vfs_ino(struct ext2_inode *inode, uint32_t inumber, struct file *parent);
void ext2_free_inode_space(struct ext2_inode *inode, ext2_fs_t *fs);

int ext2_free_block_bg(uint32_t block, uint32_t block_group, ext2_fs_t *fs);
int ext2_free_inode_bg(uint32_t inode, uint32_t block_group, ext2_fs_t *fs);

#endif
