#ifndef _LINUX_FS_H
#define _LINUX_FS_H

#include <linux/file.h>
#include <linux/module.h>
#include <linux/fs_context.h>
#include <linux/time.h>
#include <linux/kernel.h>
#include <linux/cleanup.h>

#include <onyx/vfs.h>
#include <onyx/majorminor.h>

#define address_space vm_object

#define vfsmount mount

#define i_mapping i_pages
#define super_block superblock

static inline void mapping_set_unevictable(struct address_space *mapping)
{
}

static inline void mapping_clear_unevictable(struct address_space *mapping)
{
}

static inline gfp_t mapping_gfp_mask(struct address_space *mapping)
{
    return GFP_KERNEL;
}

static inline gfp_t mapping_gfp_constraint(struct address_space *mapping, gfp_t mask)
{
    return mapping_gfp_mask(mapping) & mask;
}

void unmap_mapping_range(struct address_space *mapping, loff_t begin,
    loff_t end, int even_cows);

struct poll_table_struct;

#define file_operations file_ops
typedef mode_t umode_t;

void kill_anon_super(struct super_block *sb);

struct file_system_type {
    const char *name;
    struct module *owner;
    int (*init_fs_context)(struct fs_context *fc);
    void (*kill_sb)(struct super_block *sb);
};

int simple_pin_fs(struct file_system_type *type, struct vfsmount **mount, int *count);
int simple_release_fs(struct vfsmount **mount, int *count);
struct inode *alloc_anon_inode(struct super_block *s);

#define iput(inode) inode_unref(inode)

static inline unsigned iminor(const struct inode *inode)
{
	return MINOR(inode->i_rdev);
}

static inline unsigned imajor(const struct inode *inode)
{
	return MAJOR(inode->i_rdev);
}

#define fops_get(fops) (fops)

#define fops_put(fops) do {} while (0)

/*
 * This one is to be used *ONLY* from ->open() instances.
 * fops must be non-NULL, pinned down *and* module dependencies
 * should be sufficient to pin the caller down as well.
 */
#define replace_fops(f, fops) \
	do {	\
		struct file *__file = (f); \
		fops_put(__file->f_op); \
		BUG_ON(!(__file->f_op = (fops))); \
	} while(0)

static inline loff_t noop_llseek(struct file *file, loff_t offset, int whence)
{
	return file->f_seek;
}

#define f_pos f_seek
int register_chrdev(unsigned int major, const char *name,
				  const struct file_operations *fops);
void unregister_chrdev(unsigned int major, const char *name);

struct file *file_clone_open(struct file *file);

#define overflowuid (65534)

struct fd {
    unsigned long word;
};

#define FDGET_SHARED (1 << 0)
#define FDGET_SEEK   (1 << 1)

#define fd_file(fd) ((struct file *) ((fd).word & ~(FDGET_SEEK | FDGET_SHARED)))

static inline bool fd_empty(struct fd fd)
{
    return !fd.word;
}

struct fd linux_fdget(unsigned int fd);

static inline void fdput(struct fd fd)
{
    if (fd.word & FDGET_SHARED)
        fd_put(fd_file(fd));
}

#define fdget(fd) linux_fdget(fd)

DEFINE_CLASS(fd, struct fd, fdput(_T), fdget(fd), int fd)

#endif
