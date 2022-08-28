/*
 * Copyright (c) 2016 - 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef _EXT4_H
#define _EXT4_H

#include <errno.h>
#include <stdint.h>
#include <sys/stat.h>

#include <onyx/block.h>
#include <onyx/buffer.h>
#include <onyx/dentry.h>
#include <onyx/mutex.h>
#include <onyx/scoped_lock.h>
#include <onyx/spinlock.h>
#include <onyx/vector.h>
#include <onyx/vfs.h>

#include <onyx/expected.hpp>
#include <onyx/pair.hpp>

#define EXT4_SUPERBLOCK_OFFSET 1024

#define EXT4_SIGNATURE 0xef53

#define EXT4_VALID_FS 1
#define EXT4_ERROR_FS 2

#define EXT4_ERRORS_CONTINUE 1
#define EXT4_ERRORS_RO       2
#define EXT4_ERRORS_PANIC    3

#define EXT4_LINUX_ID    0
#define EXT4_GNU_HURD_ID 1
#define EXT4_MASIX_ID    2
#define EXT4_FREEBSD_ID  3
#define EXT4_LITES_ID    4

#define EXT4_GOOD_OLD_REV 0
#define EXT4_DYNAMIC_REV  1

#define EXT4_FEATURE_COMPAT_DIR_PREALLOC  0x01
#define EXT4_FEATURE_COMPAT_IMAGIC_INODES 0x02
#define EXT3_FEATURE_COMPAT_HAS_JOURNAL   0x04
#define EXT4_FEATURE_COMPAT_EXT_ATTR      0x08
#define EXT4_FEATURE_COMPAT_RESIZE_INO    0x10
#define EXT4_FEATURE_COMPAT_DIR_INDEX     0x20

#define EXT4_FEATURE_INCOMPAT_COMPRESSION 0x00001
#define EXT4_FEATURE_INCOMPAT_FILETYPE    0x00002
#define EXT4_FEATURE_INCOMPAT_RECOVER     0x00004
#define EXT4_FEATURE_INCOMPAT_JOURNAL_DEV 0x00008
#define EXT4_FEATURE_INCOMPAT_META_BG     0x00010
#define EXT4_FEATURE_INCOMPAT_EXTENTS     0x00040
#define EXT4_FEATURE_INCOMPAT_64BIT       0x00080
#define EXT4_FEATURE_INCOMPAT_MMP         0x00100
#define EXT4_FEATURE_INCOMPAT_FLEX_BG     0x00200
#define EXT4_FEATURE_INCOMPAT_EA_INODE    0x00400
// It's not clear whether or not this feature (below) is used right now
#define EXT4_FEATURE_INCOMPAT_DIRDATA     0x01000
#define EXT4_FEATURE_INCOMPAT_CSUM_SEED   0x02000
#define EXT4_FEATURE_INCOMPAT_LARGEDIR    0x04000
#define EXT4_FEATURE_INCOMPAT_INLINE_DATA 0x08000
#define EXT4_FEATURE_INCOMPAT_ENCRYPT     0x10000

#define EXT4_FEATURE_RO_COMPAT_SPARSE_SUPER  0x0001
#define EXT4_FEATURE_RO_COMPAT_LARGE_FILE    0x0002
#define EXT4_FEATURE_RO_COMPAT_BTREE_DIR     0x0004 // Unused
#define EXT4_FEATURE_RO_COMPAT_HUGE_FILE     0x0008
#define EXT4_FEATURE_RO_COMPAT_GDT_CSUM      0x0010
#define EXT4_FEATURE_RO_COMPAT_DIR_NLINK     0x0020
#define EXT4_FEATURE_RO_COMPAT_EXTRA_ISIZE   0x0040
#define EXT4_FEATURE_RO_COMPAT_HAS_SNAPSHOT  0x0080 // Not implemented in ext4
#define EXT4_FEATURE_RO_COMPAT_QUOTA         0x0100
#define EXT4_FEATURE_RO_COMPAT_BIGALLOC      0x0200
#define EXT4_FEATURE_RO_COMPAT_METADATA_CSUM 0x0400
#define EXT4_FEATURE_RO_COMPAT_REPLICA       0x0800 // Not used

#define EXT4_INO_TYPE_FIFO      0x1000
#define EXT4_INO_TYPE_CHARDEV   0x2000
#define EXT4_INO_TYPE_DIR       0x4000
#define EXT4_INO_TYPE_BLOCKDEV  0x6000
#define EXT4_INO_TYPE_REGFILE   0x8000
#define EXT4_INO_TYPE_SYMLINK   0xA000
#define EXT4_INO_TYPE_UNIX_SOCK 0xC000

/* Inode flags */
#define EXT4_SECRM_FL        0x00000001
#define EXT4_UNRM_FL         0x00000002
#define EXT4_COMPR_FL        0x00000004
#define EXT4_SYNC_FL         0x00000008
#define EXT4_IMMUTABLE_FL    0x00000010
#define EXT4_APPEND_FL       0x00000020
#define EXT4_NODUMP_FL       0x00000040
#define EXT4_NOATIME_FL      0x00000080
#define EXT4_DIRTY_FL        0x00000100
#define EXT4_COMPRBLK_FL     0x00000200
#define EXT4_NOCOMPR_FL      0x00000400
#define EXT4_ECOMPR_FL       0x00000800
#define EXT4_BTREE_FL        0x00001000
#define EXT4_INDEX_FL        0x00002000
#define EXT4_JOURNAL_DATA_FL 0x00004000
#define EXT4_NOTAIL_FL       0x00008000
#define EXT4_DIRSYNC_FL      0x00010000
#define EXT4_TOPDIR_FL       0x00020000
#define EXT4_HUGE_FILE_FL    0x00040000
#define EXT4_EXTENTS_FL      0x00080000
#define EXT4_VERITY_FL       0x00100000
#define EXT4_EA_INODE_FL     0x00200000
#define EXT4_RESERVED_FL     0x80000000

/* File type flags that are stored in the directory entries */
#define EXT4_FT_UNKNOWN  0
#define EXT4_FT_REG_FILE 1
#define EXT4_FT_DIR      2
#define EXT4_FT_CHRDEV   3
#define EXT4_FT_BLKDEV   4
#define EXT4_FT_FIFO     5
#define EXT4_FT_SOCK     6
#define EXT4_FT_SYMLINK  7

/**
   Checks if the opened partition has the 64-bit feature (see
EXT4_FEATURE_INCOMPAT_64BIT).
   @param[in]  Partition      Pointer to the opened ext4 partition.
   @return TRUE
*/
#define EXT4_IS_64_BIT(sb) ((sb->features_incompat & EXT4_FEATURE_INCOMPAT_64BIT) != 0)

/**
   Composes an EXT4_BLOCK_NR safely, from two halfs.
   @param[in]  sb      Pointer to the opened ext4 sb.
   @param[in]  Low            Low half of the block number.
   @param[in]  High           High half of the block number.
   @return The block number formed by Low, and if 64 bit is enabled, High.
**/
#define EXT4_BLOCK_NR_FROM_HALFS(sb, Low, High) \
    EXT4_IS_64_BIT(sb) ? ((Low) | ((uint64_t) (High) << 32)) : Low

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
    uint8_t s_jnl_backup_type;
    uint16_t s_desc_size;
    uint32_t s_default_mount_options;
    uint32_t s_first_meta_bg;
    uint32_t s_mkfs_time;
    uint32_t s_jnl_blocks[17];
    uint32_t s_blocks_count_hi;
    uint32_t s_r_blocks_count_hi;
    uint32_t s_free_blocks_count_hi;
    uint16_t s_min_extra_isize;
    uint16_t s_want_extra_isize;
    uint32_t s_flags;
    uint16_t s_raid_stride;
    uint16_t s_mmp_interval;
    uint64_t s_mmp_block;
    uint32_t s_raid_stride_width;
    uint8_t s_log_groups_per_flex;
    uint8_t s_checksum_type; // Only valid value is 1 - CRC32C
    uint16_t s_reserved_pad;
    uint64_t s_kbytes_written;

    // Snapshot stuff isn't used in Linux and isn't implemented here
    uint32_t s_snapshot_inum;
    uint32_t s_snapshot_id;
    uint64_t s_snapshot_r_blocks_count;
    uint32_t s_snapshot_list;
    uint32_t s_error_count;
    uint32_t s_first_error_time;
    uint32_t s_first_error_ino;
    uint64_t s_first_error_block;
    uint8_t s_first_error_func[32];
    uint32_t s_first_error_line;
    uint32_t s_last_error_time;
    uint32_t s_last_error_ino;
    uint32_t s_last_error_line;
    uint64_t s_last_error_block;
    uint8_t s_last_error_func[32];
    uint8_t s_mount_opts[64];
    uint32_t s_usr_quota_inum;
    uint32_t s_grp_quota_inum;
    uint32_t s_overhead_blocks;
    uint32_t s_backup_bgs[2]; // sparse_super2
    uint8_t s_encrypt_algos[4];
    uint8_t s_encrypt_pw_salt[16];
    uint32_t s_lpf_ino;
    uint32_t s_prj_quota_inum;
    uint32_t s_checksum_seed;
    uint32_t s_reserved[98];
    uint32_t s_checksum;
} __attribute__((aligned(1024), packed)) superblock_t;

typedef struct
{
    uint32_t bg_block_bitmap_lo;
    uint32_t bg_inode_bitmap_lo;
    uint32_t bg_inode_table_lo;
    uint16_t bg_free_blocks_count_lo;
    uint16_t bg_free_inodes_count_lo;
    uint16_t bg_used_dirs_count_lo;
    uint16_t bg_flags;
    uint32_t bg_exclude_bitmap_lo;
    uint16_t bg_block_bitmap_csum_lo;
    uint16_t bg_inode_bitmap_csum_lo;
    uint16_t bg_itable_unused_lo;
    uint16_t bg_checksum;
    uint32_t bg_block_bitmap_hi;
    uint32_t bg_inode_bitmap_hi;
    uint32_t bg_inode_table_hi;
    uint16_t bg_free_blocks_count_hi;
    uint16_t bg_free_inodes_count_hi;
    uint16_t bg_used_dirs_count_hi;
    uint16_t bg_itable_unused_hi;
    uint32_t bg_exclude_bitmap_hi;
    uint16_t bg_block_bitmap_csum_hi;
    uint16_t bg_inode_bitmap_csum_hi;
    uint32_t bg_reserved;
} block_group_desc_t;

#define EXT4_OLD_BLOCK_DESC_SIZE   32
#define EXT4_64BIT_BLOCK_DESC_SIZE 64

#define EXT4_DBLOCKS    12
#define EXT4_IND_BLOCK  12
#define EXT4_DIND_BLOCK 13
#define EXT4_TIND_BLOCK 14
#define EXT4_NR_BLOCKS  15

#define EXT4_GOOD_OLD_INODE_SIZE 128U

struct ext4_osd2_linux
{
    uint16_t l_i_blocks_high;
    uint16_t l_i_file_acl_high;
    uint16_t l_i_uid_high;
    uint16_t l_i_gid_high;
    uint16_t l_i_checksum_lo;
    uint16_t l_i_reserved;
};

struct ext4_osd2_hurd
{
    uint16_t h_i_reserved1;
    uint16_t h_i_mode_high;
    uint16_t h_i_uid_high;
    uint16_t h_i_gid_high;
    uint16_t h_i_author;
};

union ext4_osd2 {
    // Note: Toolchain-specific defines (such as "linux") stops us from using simpler names down
    // here.
    ext4_osd2_linux data_linux;
    ext4_osd2_hurd data_hurd;
};

struct ext4_inode
{
    uint16_t i_mode;
    uint16_t i_uid;
    uint32_t i_size_lo;
    uint32_t i_atime;
    uint32_t i_ctime;
    uint32_t i_mtime;
    uint32_t i_dtime;
    uint16_t i_gid;
    uint16_t i_links;
    uint32_t i_blocks;
    uint32_t i_flags;
    uint32_t i_os_spec;
    uint32_t i_data[EXT4_NR_BLOCKS];
    uint32_t i_generation;
    uint32_t i_file_acl;
    uint32_t i_size_hi;
    uint32_t i_faddr;
    union ext4_osd2 i_osd2;
};

#define EXT4_NAME_LEN 255

using ext4_dir_entry_t = struct
{
    uint32_t inode;
    uint16_t rec_len;
    uint8_t name_len;
    uint8_t file_type;
    char name[EXT4_NAME_LEN];
};

#define EXT4_MIN_DIR_ENTRY_LEN 8

struct ext4_superblock;

using ext4_block_group_no = uint32_t;
using ext4_inode_no = uint32_t;
using ext4_block_no = uint64_t;
using ext2_block_no = uint32_t;

class ext4_block_group
{
private:
    block_group_desc_t *bgd{};
    auto_block_buf buf{};
    ext4_block_group_no nr;
    mutex inode_bitmap_lock{};
    mutex block_bitmap_lock{};

    /* Protects used_dirs, unallocated inodes and blocks */
    spinlock lock_{};

public:
    ext4_block_group() : nr{(ext4_block_group_no) -1}
    {
        mutex_init(&inode_bitmap_lock);
        mutex_init(&block_bitmap_lock);
        spinlock_init(&lock_);
    }

    ext4_block_group(ext4_block_group_no nr_) : nr{nr_}
    {
        spinlock_init(&lock_);
        mutex_init(&inode_bitmap_lock);
        mutex_init(&block_bitmap_lock);
    }

    ext4_block_group &operator=(ext4_block_group &&rhs)
    {
        if (this == &rhs)
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

    ext4_block_group(ext4_block_group &&rhs) : nr{rhs.nr}
    {
        if (this == &rhs)
            return;

        bgd = rhs.bgd;
        buf = cul::move(rhs.buf);
        nr = cul::move(rhs.nr);
        mutex_init(&inode_bitmap_lock);
        mutex_init(&block_bitmap_lock);

        rhs.bgd = nullptr;
        rhs.buf = nullptr;
    }

    ext4_block_group &operator=(const ext4_block_group &rhs) = delete;
    ext4_block_group(const ext4_block_group &rhs) = delete;

    bool init(ext4_superblock *sb);

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
        // TODO: Adjust this for 64-bit
        bgd->bg_used_dirs_count_lo--;

        unlock();

        dirty();
    }

    void inc_used_dirs()
    {
        lock();

        bgd->bg_used_dirs_count_lo++;

        unlock();

        dirty();
    }

    /* These routines don't need locks because their mutex is already locked */

    void dec_unallocated_inodes()
    {
        bgd->bg_free_inodes_count_lo--;

        dirty();
    }

    void inc_unallocated_inodes()
    {
        bgd->bg_free_inodes_count_lo++;

        dirty();
    }

    void dec_unallocated_blocks()
    {
        lock();

        bgd->bg_free_blocks_count_lo--;

        unlock();

        dirty();
    }

    void inc_unallocated_blocks()
    {
        lock();

        bgd->bg_free_blocks_count_lo++;

        unlock();

        dirty();
    }

    block_group_desc_t *get_bgd() const
    {
        return bgd;
    }

    expected<ext4_inode_no, int> allocate_inode(ext4_superblock *sb);
    void free_inode(ext4_inode_no inode, ext4_superblock *sb);
    expected<ext4_block_no, int> allocate_block(ext4_superblock *sb);
    void free_block(ext4_block_no block, ext4_superblock *sb);

    ext4_block_no get_itable_block(const ext4_superblock *sb) const;

    auto_block_buf get_inode_table(const ext4_superblock *sb, uint32_t off) const;
};

struct block_buf;
struct ext4_superblock : public superblock
{
    mutable superblock_t *sb;
    mutable struct block_buf *sb_bb;
    uint32_t major;
    uint32_t minor;
    uint32_t total_inodes;
    uint32_t total_blocks;
    uint32_t block_size;
    uint32_t block_size_shift;
    uint32_t features_compat;
    uint32_t features_incompat;
    uint32_t features_ro_compat;
    uint32_t frag_size;
    uint32_t blocks_per_block_group;
    uint32_t inodes_per_block_group;
    uint32_t number_of_block_groups;
    uint16_t inode_size;
    uint16_t desc_size{};
    unsigned int entry_shift;
    cul::vector<ext4_block_group> block_groups;

    ext4_block_no try_allocate_block_from_bg(ext4_block_group_no nr);

public:
    ext4_superblock()
    {
        superblock_init(this);
    }

    /**
     * @brief Alocates an inode
     *
     * @return Expected consisting of a pair of the inode number and a ext4_inode *, or an
     * unexpected negative error code
     */
    expected<cul::pair<ext4_inode_no, ext4_inode *>, int> allocate_inode();

    /**
     * @brief Frees the inode
     *
     * @param ino Inode number
     */
    void free_inode(ext4_inode_no ino);

    /**
     * @brief Reports a filesystem error
     *
     * @param str Error Message
     */
    void error(const char *str) const;

    /**
     * @brief Allocates a block, taking into account the preferred block group
     *
     * @param preferred The preferred block group. If -1, no preferrence
     * @return Block number, or EXT4_ERR_INV_BLOCK if we couldn't allocate one.
     */
    ext4_block_no allocate_block(ext4_block_group_no preferred = -1);

    /**
     * @brief Frees a block
     *
     * @param block Block number to free
     */
    void free_block(ext4_block_no block);

    /**
     * @brief Read an ext4_inode from disk
     *
     * @param nr The inode number
     * @return A pointer to the inode number
     */
    ext4_inode *get_inode(ext4_inode_no nr) const;

    /**
     * @brief Updates an inode on disk
     *
     * @param ino Pointer to ext4_inode
     * @param inode_no Inode number
     */
    void update_inode(const ext4_inode *ino, ext4_inode_no inode_no);

    /**
     * @brief Reads metadata blocks from the filesystem using sb_read_block
     *
     * @param block Starting block
     * @param number_of_blocks Number of blocks
     * @param bufs Pointer to an array of N auto_block_buf's
     * @return 0 on success, negative error codes
     */
    int read_blocks(ext4_block_no block, ext4_block_no number_of_blocks, auto_block_buf *bufs);

    /**
     * @brief Get the first data block of the fs
     *
     * @return The first data block
     */
    ext4_block_no first_data_block() const
    {
        return sb->s_first_data_block;
    }

    /**
     * @brief Does statfs
     *
     * @param buf statfs struct to fill
     * @return 0 on success, negative error codes (in our case, always succesful)
     */
    int stat_fs(struct statfs *buf);

    /**
     * @brief Tries to validate the directory entry as much as possible
     *
     * @param entry Pointer to a dir entry
     * @param offset Offset of the directory entry, inside the block
     * @return True if valid, else false.
     */
    bool valid_dirent(const ext4_dir_entry_t *dentry, size_t offset);
};

struct ext4_inode_info
{
    /* Cached copy of the on-disk inode */
    struct ext4_inode *inode;
};

static inline struct ext4_inode *ext4_get_inode_from_node(struct inode *ino)
{
    assert(ino->i_helper != nullptr);
    return ((struct ext4_inode_info *) ino->i_helper)->inode;
}

#define EXT4_TYPE_DIRECT_BLOCK 0
#define EXT4_TYPE_SINGLY_BLOCK 1
#define EXT4_TYPE_DOUBLY_BLOCK 2
#define EXT4_TYPE_TREBLY_BLOCK 3

#define EXT4_DIRECT_BLOCK_COUNT 12

#define EXT4_ERR_INV_BLOCK   0
#define EXT4_FILE_HOLE_BLOCK 0

#define EXT4_GET_FILE_TYPE(mode)   ((mode) &S_IFMT)
#define EXT4_CALCULATE_SIZE64(ino) (((uint64_t) (ino)->i_size_hi << 32) | (ino)->i_size_lo)

extern const unsigned int direct_block_count;

void ext4_dirty_sb(ext4_superblock *fs);
unsigned int ext4_detect_block_type(uint32_t block, struct ext4_superblock *fs);
int ext4_add_block_to_inode(struct ext4_inode *inode, uint32_t block, uint32_t block_index,
                            struct ext4_superblock *fs);
void ext4_set_inode_size(struct ext4_inode *inode, size_t size);
int ext4_add_direntry(const char *name, uint32_t inum, ext4_inode *raw_ino, inode *dir,
                      ext4_superblock *fs);
int ext4_remove_direntry(uint32_t inum, inode *dir, ext4_superblock *fs);

int ext4_ino_type_to_vfs_type(uint16_t mode);
uint16_t ext4_mode_to_ino_type(mode_t mode);
struct inode *ext4_fs_ino_to_vfs_ino(struct ext4_inode *inode, uint32_t inumber,
                                     ext4_superblock *fs);
void ext4_free_inode_space(struct inode *inode, struct ext4_superblock *fs);
expected<ext4_block_no, int> ext4_get_block_from_inode(ext4_inode *ino, ext4_block_no block,
                                                       ext4_superblock *sb);

struct ext4_dirent_result
{
    off_t file_off;
    off_t block_off;
    char *buf;
};

int ext4_retrieve_dirent(inode *inode, const char *name, ext4_superblock *sb,
                         ext4_dirent_result *res);

struct inode *ext4_load_inode_from_disk(uint32_t inum, ext4_superblock *fs);

static inline ext4_superblock *ext4_superblock_from_inode(inode *ino)
{
    return (ext4_superblock *) ino->i_sb;
}

#define WORD_SIZE sizeof(unsigned long)
typedef uint8_t __attribute__((__may_alias__)) __bitmap_byte;

#define SCAN_ZERO_NOT_FOUND ~0UL

inline unsigned long ext4_scan_zero(unsigned long *bitmap, unsigned long size)
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

    unsigned long bit = 0;

    for (unsigned long i = 0; i < nr_words; i++, bit += bits_per_long)
    {
        if (bitmap[i] == ~0UL)
            continue;

        if (bitmap[i] == 0)
            return bit;
        else
        {
            /* We're going to have to use __builtin_ffsl here */
            unsigned int first_bit_unset = __builtin_ffsl(~bitmap[i]) - 1;

#if 0
			printk("First bit unset: %lu:%u\n", i, first_bit_unset);
			printk("bitmap[i]: %lx\n~bitmap[i]: %lx\n", bitmap[i], ~bitmap[i]);
#endif

            return bit + first_bit_unset;
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

inline uint32_t ext4_inode_number_to_bg(ext4_inode_no no, const ext4_superblock *sb)
{
    return (no - 1) / sb->inodes_per_block_group;
}

inline uint32_t ext4_block_number_to_bg(ext4_block_no block_no, const ext4_superblock *sb)
{
    return block_no / sb->blocks_per_block_group;
}

#define EXT4_ATOMIC_ADD(var, num) __atomic_add_fetch(&(var), num, __ATOMIC_RELAXED)

#define EXT4_ATOMIC_SUB(var, num) __atomic_sub_fetch(&(var), num, __ATOMIC_RELAXED)

#define EXT4_SUPPORTED_INCOMPAT EXT4_FEATURE_INCOMPAT_FILETYPE

inode *ext4_get_inode(ext4_superblock *sb, uint32_t inode_num);
inode *ext4_create_file(const char *name, mode_t mode, dev_t dev, dentry *dir);
int ext4_unlink(const char *name, int flags, dentry *dir);

/**
 * @brief Detects if a symlink is a fast symlink
 *
 * @param inode Pointer to ext4_inode struct
 * @param fs Pointer to ext4_superblock struct
 * @return True if a fast symlink, else false.
 */
bool ext4_is_fast_symlink(struct ext4_inode *inode, struct ext4_superblock *fs);

#define EXT4_MIN_DIR_ENTRY_LEN 8

// This on-disk structure is present at the bottom of the extent tree
struct ext4_extent
{
    // First logical block
    uint32_t ee_block;
    // Length of the extent, in blocks
    uint16_t ee_len;
    // The physical (filesystem-relative) block is split between the high 16 bits
    // and the low 32 bits - this forms a 48-bit block number
    uint16_t ee_start_hi;
    uint32_t ee_start_lo;
};

// This on-disk structure is present at all levels except the bottom
struct ext4_extent_index
{
    // This index covers logical blocks from 'ei_block'
    uint32_t ei_block;
    // Block of the next level of the extent tree, similarly split in a high and
    // low portion.
    uint32_t ei_leaf_lo;
    uint16_t ei_leaf_hi;

    uint16_t ei_unused;
};

struct ext4_extent_header
{
    // Needs to be EXT4_EXTENT_HEADER_MAGIC
    uint16_t eh_magic;
    // Number of entries
    uint16_t eh_entries;
    // Maximum number of entries that could follow this header
    uint16_t eh_max;
    // Depth of this node in the tree - the tree can be at most 5 levels deep
    uint16_t eh_depth;
    // Unused by standard ext4
    uint32_t eh_generation;
};

#define EXT4_EXTENT_HEADER_MAGIC 0xF30A

// Specified by ext4 docs and backed by a bunch of math
#define EXT4_EXTENT_TREE_MAX_DEPTH 5

struct ext4_extent_tail
{
    // CRC32C of UUID + inode number + igeneration + extent block
    uint32_t eb_checksum;
};

/**
 * EXT4 has this feature called uninitialized extents:
 * An extent has a maximum of 32768 blocks (2^15 or 1 << 15).
 * When we find an extent with > 32768 blocks, this extent is called
 * uninitialized. Long story short, it's an extent that behaves as a file hole
 * but has blocks already allocated.
 */
#define EXT4_EXTENT_MAX_INITIALIZED (1 << 15)

/**
 * @brief Get the underlying block from a logical block, for a given inode
 *
 * @param sb Superblock
 * @param ino Inode
 * @param block Logical block
 * @return ext4 block, or a negative error number
 */
expected<ext4_block_no, int> ext4_bmap_get_block(ext4_superblock *sb, ext4_inode *ino,
                                                 ext4_block_no block);

/**
 * @brief Get the underlying block from a logical block, for a given inode
 *
 * @param sb Superblock
 * @param ino Inode
 * @param block Logical block
 * @return ext4 block, or a negative error number
 */
expected<ext4_block_no, int> ext4_emap_get_block(ext4_superblock *sb, ext4_inode *ino,
                                                 ext4_block_no block);

/**
 * @brief Create the path and allocate a block
 *
 * @param ino Inode
 * @param block Block to create the path too
 * @param sb Superblock
 * @return Allocated block number, or negative error number
 */
expected<ext4_block_no, int> ext4_bmap_create_path(inode *ino, ext4_block_no block,
                                                   ext4_superblock *sb);

/**
 * @brief Truncates inode blocks for bmap inodes
 *
 * @param new_len New length
 * @param ino Pointer to inode
 * @return 0 on success, negative error codes
 */
int ext4_bmap_truncate_inode_blocks(size_t new_len, inode *ino);

#endif
