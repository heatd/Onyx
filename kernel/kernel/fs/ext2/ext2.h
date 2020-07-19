/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _EXT2_H
#define _EXT2_H

#include <stdint.h>
#include <errno.h>

#include <onyx/mutex.h>
#include <onyx/spinlock.h>
#include <onyx/block.h>
#include <onyx/vfs.h>
#include <onyx/vector.h>
#include <onyx/scoped_lock.h>
#include <onyx/pair.hpp>
#include <onyx/expected.hpp>

#include <onyx/buffer.h>

#define EXT2_SUPERBLOCK_OFFSET		1024

#define EXT2_SIGNATURE		0xef53

#define EXT2_VALID_FS        1
#define EXT2_ERROR_FS        2

#define EXT2_ERRORS_CONTINUE 1
#define EXT2_ERRORS_RO       2
#define EXT2_ERRORS_PANIC    3

#define EXT2_LINUX_ID        0
#define EXT2_GNU_HURD_ID     1
#define EXT2_MASIX_ID        2
#define EXT2_FREEBSD_ID      3
#define EXT2_LITES_ID        4

#define EXT2_GOOD_OLD_REV    0
#define EXT2_DYNAMIC_REV     1

#define EXT2_FEATURE_COMPAT_DIR_PREALLOC          1
#define EXT2_FEATURE_COMPAT_IMAGIC_INODES         2
#define EXT3_FEATURE_COMPAT_HAS_JOURNAL           4
#define EXT2_FEATURE_COMPAT_EXT_ATTR              8
#define EXT2_FEATURE_COMPAT_RESIZE_INO            0x10
#define EXT2_FEATURE_COMPAT_DIR_INDEX             0x20

#define EXT2_FEATURE_INCOMPAT_COMPRESSION         0x1
#define EXT2_FEATURE_INCOMPAT_FILETYPE            0x2
#define EXT2_FEATURE_INCOMPAT_RECOVER             0x4
#define EXT2_FEATURE_INCOMPAT_JOURNAL_DEV         0x8
#define EXT2_FEATURE_INCOMPAT_META_BG             0x10

#define EXT2_FEATURE_RO_COMPAT_SPARSE_SUPER       1
#define EXT2_FEATURE_RO_COMPAT_LARGE_FILE         2
#define EXT2_FEATURE_RO_COMPAT_BTREE_DIR          4

#define EXT2_INO_TYPE_FIFO                       0x1000
#define EXT2_INO_TYPE_CHARDEV                    0x2000
#define EXT2_INO_TYPE_DIR                        0x4000
#define EXT2_INO_TYPE_BLOCKDEV                   0x6000
#define EXT2_INO_TYPE_REGFILE                    0x8000
#define EXT2_INO_TYPE_SYMLINK                    0xA000
#define EXT2_INO_TYPE_UNIX_SOCK                  0xC000

/* Inode flags */
#define EXT2_SECRM_FL                    0x1
#define EXT2_UNRM_FL                     0x2
#define EXT2_COMPR_FL                    0x4
#define EXT2_SYNC_FL                     0x8
#define EXT2_IMMUTABLE_FL                0x10
#define EXT2_APPEND_FL                   0x20
#define EXT2_NODUMP_FL                   0x40
#define EXT2_NOATIME_FL                  0x80
#define EXT2_DIRTY_FL                    0x100
#define EXT2_COMPRBLK_FL                 0x200
#define EXT2_NOCOMPR_FL                  0x400
#define EXT2_ECOMPR_FL                   0x800
#define EXT2_BTREE_FL                    0x1000
#define EXT2_INDEX_FL                    0x2000
#define EXT3_JOURNAL_DATA_FL             0x4000
#define EXT2_RESERVED_FL                 0x80000000

/* File type flags that are stored in the directory entries */
#define EXT2_FT_UNKNOWN         0
#define EXT2_FT_REG_FILE        1
#define EXT2_FT_DIR             2
#define EXT2_FT_CHRDEV          3
#define EXT2_FT_BLKDEV          4
#define EXT2_FT_FIFO            5
#define EXT2_FT_SOCK            6
#define EXT2_FT_SYMLINK         7

typedef struct
{
	uint32_t s_inodes_count;
	uint32_t s_blocks_count;
	uint32_t s_r_blocks_count;
	uint32_t s_free_blocks_count;
	uint32_t s_free_inodes_count;
	uint32_t s_first_data_block;
	uint32_t s_log_block_size;
	uint32_t s_log_frag_size;
	uint32_t s_blocks_per_group;
	uint32_t s_frags_per_group;
	uint32_t s_inodes_per_group;
	uint32_t s_mtime;
	uint32_t s_wtime;
	uint16_t s_mnt_count;
	uint16_t s_max_mnt_count;
	uint16_t s_magic;
	uint16_t s_state;
	uint16_t s_errors;
	uint16_t s_minor_rev_level;
	uint32_t s_lastcheck;
	uint32_t s_check_interval;
	uint32_t s_creator_os;
	uint32_t s_rev_level;
	uint16_t s_def_resuid;
	uint16_t s_def_resgid;


	/* Every field after this comment is revision >= 1 */

	uint32_t s_first_ino;
	uint16_t s_inode_size;
	uint16_t s_block_group_nr;
	uint32_t s_feature_compat;
	uint32_t s_feature_incompat;
	uint32_t s_feature_ro_compat;
	uint8_t s_uuid[16];
	uint8_t s_volume_name[16];
	uint8_t s_last_mounted[64];
	uint32_t s_algo_bitmap;
	uint8_t s_prealloc_blocks;
	uint8_t s_prealloc_dir_blocks;
	uint16_t unused;
	uint8_t s_journal_uuid[16];
	uint32_t s_journal_inum;
	uint32_t s_journal_dev;
	uint32_t s_last_orphan;
	uint32_t s_hash_seed[4];
	uint8_t s_def_hash_version;
	uint32_t s_default_mount_options;
	uint32_t s_first_meta_bg;
} __attribute__((aligned(1024), packed)) superblock_t;

typedef struct
{
	uint32_t block_usage_addr;
	uint32_t inode_usage_addr;
	uint32_t inode_table_addr;
	uint16_t unallocated_blocks_in_group;
	uint16_t unallocated_inodes_in_group;
	uint16_t used_dirs_count;
} __attribute__((aligned(32))) block_group_desc_t;

#define EXT2_DBLOCKS       12
#define EXT2_IND_BLOCK     12
#define EXT2_DIND_BLOCK    13
#define EXT2_TIND_BLOCK    14
#define EXT2_NR_BLOCKS     15

#define EXT2_GOOD_OLD_INODE_SIZE 128
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
	uint32_t i_data[EXT2_NR_BLOCKS];
	uint32_t i_generation;
	uint32_t i_file_acl;
	uint32_t size_hi;
	uint32_t i_faddr;
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

struct ext2_superblock;

using ext2_block_group_no = uint32_t;
using ext2_inode_no = uint32_t;
using ext2_block_no = uint32_t;

class ext2_block_group
{
private:
	block_group_desc_t *bgd{};
	auto_block_buf buf{};
	ext2_block_group_no nr;
	mutex inode_bitmap_lock{};
	mutex block_bitmap_lock{};

	/* Protects used_dirs, unallocated inodes and blocks */
	spinlock lock_{};
public:

	ext2_block_group() : buf{}, nr{(ext2_block_group_no) -1}
	{
		mutex_init(&inode_bitmap_lock);
		mutex_init(&block_bitmap_lock);
		spinlock_init(&lock_);
	}

	ext2_block_group(ext2_block_group_no nr_) : nr{nr_}
	{
		spinlock_init(&lock_);
		mutex_init(&inode_bitmap_lock);
		mutex_init(&block_bitmap_lock);
	} 

	ext2_block_group& operator=(ext2_block_group&& rhs)
	{
		if(this == &rhs)
			return *this;

		bgd = rhs.bgd;
		buf = cul::move(rhs.buf);
		nr = cul::move(rhs.nr);
		mutex_init(&inode_bitmap_lock);
		mutex_init(&block_bitmap_lock);

		rhs.bgd = nullptr;
		rhs.buf = nullptr;

		return *this;
	}

	ext2_block_group(ext2_block_group&& rhs) : nr{rhs.nr}
	{
		if(this == &rhs)
			return;

		bgd = rhs.bgd;
		buf = cul::move(rhs.buf);
		nr = cul::move(rhs.nr);
		mutex_init(&inode_bitmap_lock);
		mutex_init(&block_bitmap_lock);

		rhs.bgd = nullptr;
		rhs.buf = nullptr;
	}

	ext2_block_group& operator=(const ext2_block_group& rhs) = delete;
	ext2_block_group(const ext2_block_group& rhs) = delete;

	bool init(ext2_superblock *sb);

	void lock()
	{
		spin_lock(&lock_);
	}

	void unlock()
	{
		spin_unlock(&lock_);
	}

	void dirty()
	{
		block_buf_dirty(buf);
	}

	void dec_used_dirs()
	{
		lock();

		bgd->used_dirs_count--;

		unlock();

		dirty();
	}

	void inc_used_dirs()
	{
		lock();

		bgd->used_dirs_count++;

		unlock();

		dirty();
	}

	/* These routines don't need locks because their mutex is already locked */

	void dec_unallocated_inodes()
	{
		bgd->unallocated_inodes_in_group--;

		dirty();
	}

	void inc_unallocated_inodes()
	{
		bgd->unallocated_inodes_in_group++;

		dirty();
	}

	void dec_unallocated_blocks()
	{
		lock();

		bgd->unallocated_blocks_in_group--;

		unlock();

		dirty();
	}

	void inc_unallocated_blocks()
	{
		lock();

		bgd->unallocated_blocks_in_group++;

		unlock();

		dirty();
	}

	block_group_desc_t *get_bgd() const
	{
		return bgd;
	}

	expected<ext2_inode_no, int> allocate_inode(ext2_superblock *sb);
	void free_inode(ext2_inode_no inode, ext2_superblock *sb);
	expected<ext2_inode_no, int> allocate_block(ext2_superblock *sb);
	void free_block(ext2_block_no block, ext2_superblock *sb);

	auto_block_buf get_inode_table(const ext2_superblock *sb, uint32_t off) const;
};

struct block_buf;
struct ext2_superblock : public superblock
{
	mutable superblock_t *sb;
	mutable struct block_buf *sb_bb;
	uint32_t major;
	uint32_t minor;
	uint32_t total_inodes;
	uint32_t total_blocks;
	uint32_t block_size;
	uint32_t features_compat;
	uint32_t features_incompat;
	uint32_t features_ro_compat;
	uint32_t frag_size;
	uint32_t blocks_per_block_group;
	uint32_t inodes_per_block_group;
	uint32_t number_of_block_groups;
	uint16_t inode_size;
	unsigned int entry_shift;
	cul::vector<ext2_block_group> block_groups;

	ext2_block_no try_allocate_block_from_bg(ext2_block_group_no nr);

public:
	ext2_superblock()
	{
		superblock_init(this);
	}

	expected<cul::pair<ext2_inode_no, ext2_inode *>, int> allocate_inode();
	void free_inode(ext2_inode_no ino);
	void error(const char *str) const;

	ext2_block_no allocate_block(ext2_block_group_no preferred = -1);
	void free_block(ext2_block_no block);

	ext2_inode *get_inode(ext2_inode_no nr) const;
	void update_inode(ext2_inode *ino, ext2_inode_no inode_no);

	int read_blocks(ext2_block_no block, ext2_block_no number_of_blocks, auto_block_buf *bufs);

};

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
#define EXT2_FILE_HOLE_BLOCK    0

#define EXT2_GET_FILE_TYPE(mode) (mode & 0xE000)
#define EXT2_CALCULATE_SIZE64(ino) (((uint64_t)ino->size_hi << 32) | ino->size_lo)

extern const unsigned int direct_block_count;

void ext2_dirty_sb(ext2_superblock *fs);
unsigned int ext2_detect_block_type(uint32_t block, struct ext2_superblock *fs);
int ext2_add_block_to_inode(struct ext2_inode *inode, uint32_t block,
	uint32_t block_index, struct ext2_superblock *fs);
void ext2_set_inode_size(struct ext2_inode *inode, size_t size);
int ext2_add_direntry(const char *name, uint32_t inum, ext2_inode *raw_ino,
	inode *dir, ext2_superblock *fs);
int ext2_remove_direntry(uint32_t inum, inode *dir, ext2_superblock *fs);

int ext2_ino_type_to_vfs_type(uint16_t mode);
uint16_t ext2_mode_to_ino_type(mode_t mode);
struct inode *ext2_fs_ino_to_vfs_ino(struct ext2_inode *inode, uint32_t inumber, ext2_superblock *fs);
void ext2_free_inode_space(struct ext2_inode *inode, struct ext2_superblock *fs);
expected<ext2_block_no, int> ext2_get_block_from_inode(ext2_inode *ino, ext2_block_no block, ext2_superblock *sb);

struct ext2_dirent_result
{
	off_t file_off;
	off_t block_off;
	char *buf;
};

int ext2_retrieve_dirent(inode *inode, const char *name, ext2_superblock *sb,
			ext2_dirent_result *res);

struct inode *ext2_load_inode_from_disk(uint32_t inum, ext2_superblock *fs);

static inline ext2_superblock *ext2_superblock_from_inode(inode *ino)
{
	return (ext2_superblock *) ino->i_sb;
}

#define WORD_SIZE           sizeof(unsigned long)
typedef uint8_t __attribute__((__may_alias__)) __bitmap_byte;

#define SCAN_ZERO_NOT_FOUND			~0UL

#include <stdio.h>

inline unsigned long ext2_scan_zero(unsigned long *bitmap, unsigned long size)
{
	size_t nr_words = size / WORD_SIZE;
	static constexpr auto bits_per_long = WORD_SIZE * CHAR_BIT;

	/* I don't believe we need to handle trailing bytes here, since block sizes are
	 * pretty much guaranteed to be word aligned.
	 */
#if 0
	size_t trailing_bytes = size % WORD_SIZE;
#endif

#if 0
	printk("Nr words: %lu\n", size);
#endif

	for(unsigned long i = 0; i < nr_words; i++)
	{
		if(bitmap[i] == ~0UL)
			continue;
		
		if(bitmap[i] == 0)
			return i * bits_per_long;
		else
		{
			/* We're going to have to use builtin_clz here */
			unsigned int first_bit_unset = __builtin_ffs(~bitmap[i]) - 1;

		#if 0
			printk("First bit unset: %u\n", first_bit_unset);
		#endif

			return i * bits_per_long + first_bit_unset;
		}
	}

#if 0
	if(trailing_bytes)
	{
		__bitmap_byte *b = (__bitmap_byte *)(&bitmap[nr_words]);

		for(unsigned long i = 0; i < trailing_bytes; i++)
		{
			if(b[i] == UINT8_MAX)
			continue;
		
			if(b[i] == 0)
				return i * nr_words;
			else
			{
				/* We're going to have to use builtin_clz here */
				unsigned int first_bit_unset = __builtin_clz(b[i]);

				return i * nr_words + first_bit_unset;
			}
		} 
	}
#endif

	return SCAN_ZERO_NOT_FOUND;
}

inline uint32_t ext2_inode_number_to_bg(ext2_inode_no no, const ext2_superblock *sb)
{
	return (no - 1) / sb->inodes_per_block_group;
}

inline uint32_t ext2_block_number_to_bg(ext2_block_no block_no, const ext2_superblock *sb)
{
	return block_no / sb->blocks_per_block_group;
}

#define EXT2_ATOMIC_ADD(var, num)    \
__atomic_add_fetch(&var, num, __ATOMIC_RELAXED)

#define EXT2_ATOMIC_SUB(var, num)    \
__atomic_sub_fetch(&var, num, __ATOMIC_RELAXED)


#define EXT2_SUPPORTED_INCOMPAT   EXT2_FEATURE_INCOMPAT_FILETYPE

#endif
