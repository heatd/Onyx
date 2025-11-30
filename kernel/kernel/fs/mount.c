/*
 * Copyright (c) 2024 - 2025 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <stdio.h>
#include <sys/mount.h>

#include <onyx/compiler.h>
#include <onyx/cred.h>
#include <onyx/dentry.h>
#include <onyx/err.h>
#include <onyx/file.h>
#include <onyx/fs_mount.h>
#include <onyx/list.h>
#include <onyx/mm/slab.h>
#include <onyx/mount.h>
#include <onyx/namei.h>
#include <onyx/proc.h>
#include <onyx/rculist.h>
#include <onyx/rcupdate.h>
#include <onyx/seq_file.h>
#include <onyx/seqlock.h>
#include <onyx/user.h>
#include <onyx/vfs.h>

struct blockdev;
/* HACK! block.h is not C compatible */
int bdev_do_open(struct blockdev *bdev, bool exclusive);
void bdev_release(struct blockdev *bdev);
static inline struct blockdev *blkdev_get_dev(struct file *f)
{
    return (struct blockdev *) f->f_ino->i_helper;
}

#define MT_HASH_SIZE 32

static struct list_head mount_hashtable[MT_HASH_SIZE];
static struct list_head mp_hashtable[MT_HASH_SIZE];
static DEFINE_LIST(mount_list);

seqlock_t mount_lock;

static void mnt_init(struct mount *mnt, unsigned long flags)
{
    mnt->mnt_count = mnt->mnt_writecount = 0;
    mnt->mnt_flags = flags;
    mnt->mnt_point = mnt->mnt_root = NULL;
    mnt->mnt_sb = NULL;
    mnt->mnt_parent = NULL;
    INIT_LIST_HEAD(&mnt->mnt_submounts);
}

static unsigned int mnt_hashbucket(struct mount *mnt)
{
    return fnv_hash(&mnt->mnt_root, sizeof(void *)) & (MT_HASH_SIZE - 1);
}

static unsigned int mnt_mp_hashbucket(struct mount *mnt)
{
    return fnv_hash(&mnt->mnt_point, sizeof(void *)) & (MT_HASH_SIZE - 1);
}

static struct mount *mnt_find_by_mp(struct dentry *mountpoint)
{
    /* rcu_read_lock held */
    unsigned int bucket = fnv_hash(&mountpoint, sizeof(void *)) & (MT_HASH_SIZE - 1);
    list_for_every_rcu (&mp_hashtable[bucket])
    {
        struct mount *mnt = container_of(l, struct mount, mnt_mp_node);
        if (mnt->mnt_point == mountpoint)
            return mnt;
    }

    return NULL;
}

struct mount *mnt_traverse(struct dentry *mountpoint)
{
    /* All of this runs under rcu_read_lock. We use a seqlock to make sure we safely traverse
     * from one mountpoint to another. */
    unsigned int seq = 0;
    struct mount *mnt = NULL;
    rcu_read_lock();
    /* TODO: Traverse stacked mounts properly (i.e mount /tmp mount /tmp mount /tmp)*/

    do
    {
        if (mnt)
            mnt_put(mnt);
        mnt = NULL;
        seq = read_seqbegin(&mount_lock);
        mnt = mnt_find_by_mp(mountpoint);
        if (!mnt)
            break;
        mnt_get(mnt);

        smp_mb();
        if (mnt->mnt_flags & MNT_DOOMED)
        {
            mnt_put(mnt);
            mnt = NULL;
        }
    } while (read_seqretry(&mount_lock, seq));

    rcu_read_unlock();
    return mnt;
}

static struct blockdev *resolve_bdev(const char *source, struct fs_mount *fs)
{
    int ret = 0;
    if (fs->flags & FS_MOUNT_PSEUDO_FS)
    {
        // Pseudo fs's dont have a backing block device
        return NULL;
    }

    struct file *block_file = c_vfs_open(AT_FDCWD, source, O_RDWR, 0);
    if (IS_ERR(block_file))
    {
        ret = -ENOENT;
        goto err;
    }

    if (!S_ISBLK(block_file->f_ino->i_mode))
    {
        ret = -ENOTBLK;
        fd_put(block_file);
        goto err;
    }

    struct blockdev *bdev = blkdev_get_dev(block_file);
    if (bdev_do_open(bdev, false) < 0)
    {
        /* This shouldn't happen, but handle it anyway */
        ret = -EIO;
        fd_put(block_file);
        goto err;
    }

    fd_put(block_file);
    return bdev;
err:
    return (struct blockdev *) ERR_PTR(ret);
}

static struct superblock *fs_prepare_mount(struct dentry *root, struct blockdev *bdev,
                                           struct fs_mount *fs, unsigned long flags)
{
    struct vfs_mount_info info;
    info.bdev = bdev;
    info.mnt_flags = flags;
    info.root_dir = root;
    return fs->mount(&info);
}

static bool check_created_mnt(struct mount *mnt)
{
    if (WARN_ON(IS_ERR_OR_NULL(mnt->mnt_root)))
        return false;
    if (WARN_ON(d_is_negative(mnt->mnt_root)))
        return false;
    if (WARN_ON(IS_ERR_OR_NULL(mnt->mnt_sb)))
        return false;
    return true;
}

static int mnt_commit(struct mount *mnt, const char *target)
{
    /* Mounting on root is a special case. There, we just replace the fs root and don't need to set
     * flags on a dentry, etc. */
    if (strcmp(target, "/"))
    {
        struct path mountpoint;
        int err;

        err = path_openat(AT_FDCWD, target, LOOKUP_MUST_BE_DIR, &mountpoint);
        if (err < 0)
            return err;

        /* Path reference gets dilluted into these two members */
        mnt->mnt_point = mountpoint.dentry;
        mnt->mnt_parent = mountpoint.mount;
    }
    else if (!(mnt->mnt_flags & MS_KERNMOUNT))
    {
        /* TODO: This is weird and complicated, given that our boot_root doesn't really match after
         * we chroot. In any case, mount on / should generally disallowed, apart from the first
         * mount of all. We don't handle this properly. */
        struct path p = {mnt->mnt_root, mnt};
        if (set_root(&p) < 0)
            return -EBUSY;
    }

    /* Register this mount on the table */
    write_seqlock(&mount_lock);

    list_add_tail(&mnt->mnt_mp_node, &mp_hashtable[mnt_mp_hashbucket(mnt)]);
    list_add_tail(&mnt->mnt_node, &mount_hashtable[mnt_hashbucket(mnt)]);
    list_add_tail(&mnt->mnt_namespace_node, &mount_list);

    if (mnt->mnt_parent)
        list_add_tail(&mnt->mnt_submount_node, &mnt->mnt_parent->mnt_submounts);

    /* Ref up for the mount root */
    dget(mnt->mnt_root);

    if (mnt->mnt_point)
        __atomic_or_fetch(&mnt->mnt_point->d_flags, DENTRY_FLAG_MOUNTPOINT, __ATOMIC_RELEASE);

    write_sequnlock(&mount_lock);

    return 0;
}

static bool mnt_rdonly(struct mount *mnt)
{
    struct superblock *sb = mnt->mnt_sb;

    return (READ_ONCE(mnt->mnt_flags) & MNT_READONLY) || sb_rdonly(sb);
}

static bool mnt_may_write(struct mount *mnt)
{
    struct superblock *sb = mnt->mnt_sb;

    if (READ_ONCE(sb->s_remount_ro_pending))
        return false;
    return !mnt_rdonly(mnt);
}

int mnt_get_write_access(struct mount *mnt)
{
    /* Increment the mnt_writecount first, before we check for RO, etc */
    __atomic_add_fetch(&mnt->mnt_writecount, 1, __ATOMIC_RELAXED);
    /* This pairs with read-only marking code, and makes sure the writecount store is visible before
     * our WRITE_HOLD reads */
    smp_mb();

    /* If MNT_WRITE_HOLD is set, someone is modifying the writeability of this mount/superblock. In
     * such a case, wait until the operation is finished. */
    while (READ_ONCE(mnt->mnt_flags) & MNT_WRITE_HOLD)
        cpu_relax();

    /* Order the WRITE_HOLD reads against this READONLY read, otherwise we could observe stale state
     */
    smp_rmb();
    if (!mnt_may_write(mnt))
    {
        __atomic_sub_fetch(&mnt->mnt_writecount, 1, __ATOMIC_RELAXED);
        return -EROFS;
    }

    return 0;
}

static int mnt_hold_writers(struct mount *mnt)
{
    mnt->mnt_flags |= MNT_WRITE_HOLD;
    /* This memory barriers pairs with the smp_mb() in mnt_get_write_access. If someone observes our
     * write hold, we will have observed their writecount bump. */
    smp_mb();

    if (READ_ONCE(mnt->mnt_writecount) > 0)
        return -EBUSY;

    return 0;
}

static int sb_start_ro(struct superblock *sb)
{
    /* sb->s_lock held */
    struct mount *mnt;
    int err = 0;

    list_for_each_entry (mnt, &sb->s_mounts, mnt_sb_node)
    {
        err = mnt_hold_writers(mnt);
        if (err)
        {
            /* Mount has writers. Shame. Back out. */
            goto out;
        }
    }

    WRITE_ONCE(sb->s_remount_ro_pending, 1);
    /* This barrier pairs against the one in mnt_get_write_access. If it observes MNT_WRITE_HOLD
     * clear, it will also observe s_remount_ro_pending. */
    smp_wmb();
out:
    list_for_each_entry (mnt, &sb->s_mounts, mnt_sb_node)
        mnt->mnt_flags &= ~MNT_WRITE_HOLD;
    return err;
}

static void sb_end_ro(struct superblock *sb)
{
    /* Make sure precending stores are observed in mnt_get_write_access, i.e s_flags changes */
    smp_wmb();
    WRITE_ONCE(sb->s_remount_ro_pending, 0);
}

void mnt_put_write(struct mount *mnt)
{
    __atomic_sub_fetch(&mnt->mnt_writecount, 1, __ATOMIC_RELAXED);
}

static struct mount *do_mount_internal(const char *source, const char *target, struct fs_mount *fs,
                                       unsigned long mnt_flags, unsigned int sb_flags,
                                       const void *data)
{
    struct blockdev *bdev = NULL;
    struct dentry *root_dentry;
    struct mount *mnt;
    int ret = -ENODEV;

    bdev = resolve_bdev(source, fs);
    if (IS_ERR(bdev))
        return (void *) bdev;

    ret = -ENOMEM;
    mnt = kmalloc(sizeof(*mnt), GFP_KERNEL);
    if (!mnt)
        goto out;
    mnt_init(mnt, mnt_flags);

    root_dentry = dentry_create("", NULL, NULL, DENTRY_FLAG_MOUNT_ROOT | DENTRY_FLAG_NEGATIVE);
    if (!root_dentry)
        goto out2;

    mnt->mnt_sb = fs_prepare_mount(root_dentry, bdev, fs, mnt_flags);
    if (IS_ERR(mnt->mnt_sb))
    {
        ret = PTR_ERR(mnt->mnt_sb);
        mnt->mnt_sb = NULL;
        goto out3;
    }

    list_add_tail(&mnt->mnt_sb_node, &mnt->mnt_sb->s_mounts);
    bdev = NULL;
    mnt->mnt_root = root_dentry;
    mnt->mnt_sb->s_type = fs;
    mnt->mnt_devname = source;
    root_dentry = NULL;

    WARN_ON(!sb_check_callbacks(mnt->mnt_sb));

    if (!check_created_mnt(mnt))
    {
        ret = -EIO;
        goto out3;
    }

    ret = mnt_commit(mnt, target);
    if (ret == 0)
        return mnt;
out3:
    if (root_dentry)
        dput(root_dentry);
out2:
    if (mnt)
        kfree(mnt);
out:
    if (bdev)
        bdev_release(bdev);
    return ERR_PTR(ret);
}

struct mount *kern_mount(struct fs_mount *fs)
{
    return do_mount_internal(fs->name, "/", fs, MS_KERNMOUNT, MS_KERNMOUNT, NULL);
}

static int do_remount_sb(struct superblock *sb, unsigned int sb_flags)
{
    /* Superblock write-locked. Do the actual remount for the super, and don't forget to deal with
     * any mount BS that we may need. */
    bool rdonly = sb_rdonly(sb);
    int err = 0;

    if (!rdonly && sb_flags & SB_RDONLY)
    {
        /* Remounting read-only. Make sure we hold every mount properly */
        err = sb_start_ro(sb);
        if (err)
            return err;
    }

    if (sb->s_ops->reconfigure)
    {
        err = sb->s_ops->reconfigure(sb, sb_flags);
        if (err)
        {
            pr_warn("super: superblock reconfigure (for filesystem %s) failed: %d\n",
                    sb->s_type->name, err);
            goto err;
        }
    }

    WRITE_ONCE(sb->s_flags, (READ_ONCE(sb->s_flags) & SB_INTERNAL_FLAGS) | sb_flags);

err:
    sb_end_ro(sb);
    return err;
}

static struct mount *do_remount(const char *target, unsigned int sb_flags, unsigned long mnt_flags,
                                const void *data)
{
    struct path path;
    struct mount *mnt;
    struct superblock *sb;
    int err;

    err = path_openat(AT_FDCWD, target, 0, &path);
    if (err)
        return ERR_PTR(err);

    mnt = path.mount;
    if (path.dentry != mnt->mnt_root)
    {
        /* Not the root, error out */
        err = -EINVAL;
        goto out;
    }

    /* Grab the sb (from the mount) and do the actual sb remount. We use s_lock to serialize against
     * other changes. */
    sb = mnt->mnt_sb;
    rw_lock_write(&sb->s_lock);
    err = do_remount_sb(sb, sb_flags);
    /* TODO: Re-calculate mnt_flags */
    rw_unlock_write(&sb->s_lock);

out:
    path_put(&path);
    return err ? ERR_PTR(err) : mnt;
}

#define VALID_MOUNT_FLAGS \
    (MS_RDONLY | MS_SILENT | MS_RELATIME | MS_REMOUNT | MS_BIND | MS_STRICTATIME | MS_NOATIME)

/* These flags have the same bits internally as in the argument */
#define SAME_FLAGS_MASK (MNT_STRICTATIME | MNT_NOATIME | MNT_NODIRATIME | MNT_READONLY)

static unsigned long translate_mount_flags(unsigned long flags)
{
    unsigned long mflags = flags & SAME_FLAGS_MASK;

    return mflags;
}

int do_mount(const char *source, const char *target, const char *fstype, unsigned long flags,
             const void *data)
{
    struct fs_mount *fs;
    struct mount *mnt;
    unsigned long mnt_flags;
    unsigned int sb_flags;

    /* Find the fstype's handler */
    fs = fs_mount_get(fstype);
    if (!fs)
        return -ENODEV;

    if (flags & ~VALID_MOUNT_FLAGS)
        return -EINVAL;

    mnt_flags = translate_mount_flags(flags);
    sb_flags = flags & (SB_RDONLY | SB_SILENT);

    if ((flags & (MS_REMOUNT | MS_BIND)) == MS_REMOUNT)
        mnt = do_remount(target, sb_flags, mnt_flags, data);
    else
        mnt = do_mount_internal(source, target, fs, mnt_flags, sb_flags, data);
    if (IS_ERR(mnt))
        return PTR_ERR(mnt);
    return 0;
}

int sys_mount(const char *usource, const char *utarget, const char *ufilesystemtype,
              unsigned long mountflags, const void *data)
{
    const char *source = NULL;
    const char *target = NULL;
    const char *filesystemtype = NULL;
    int ret = 0;

    if (!is_root_user())
        return -EPERM;

    source = strcpy_from_user(usource);
    if (!source)
    {
        ret = -errno;
        goto out;
    }

    target = strcpy_from_user(utarget);
    if (!target)
    {
        ret = -errno;
        goto out;
    }

    filesystemtype = strcpy_from_user(ufilesystemtype);
    if (!filesystemtype)
    {
        ret = -errno;
        goto out;
    }

    ret = do_mount(source, target, filesystemtype, mountflags, data);
    if (ret == 0)
        source = NULL;
out:
    if (target)
        free((void *) target);
    if (filesystemtype)
        free((void *) filesystemtype);
    return ret;
}

/* HACK */
#define LOOKUP_NOFOLLOW                (1 << 0)
#define LOOKUP_FAIL_IF_LINK            (1 << 1)
#define LOOKUP_MUST_BE_DIR             (1 << 2)
#define LOOKUP_INTERNAL_TRAILING_SLASH (1 << 3)
#define LOOKUP_EMPTY_PATH              (1 << 4)
#define LOOKUP_DONT_DO_LAST_NAME       (1 << 5)
#define LOOKUP_INTERNAL_SAW_LAST_NAME  (1U << 31)

static bool attempt_disconnect(struct mount *mount)
{
    bool ok = false;
    write_seqlock(&mount_lock);
    /* No one can grab a reference to a mount while we hold mount_lock. As such, checking the refs
     * here is mostly safe. Note that we can spuriouly see a ref-up here, but that's not _really_ a
     * problem. We expect a mnt_count of 1 for the struct path we hold. */
    smp_mb();
    if (mount->mnt_count == 1)
    {
        struct dentry *mp = mount->mnt_point;
        list_remove(&mount->mnt_mp_node);
        list_remove(&mount->mnt_node);
        list_remove(&mount->mnt_namespace_node);
        if (mount->mnt_parent)
        {
            list_remove(&mount->mnt_submount_node);
            mnt_put(mount->mnt_parent);
        }

        ok = true;

        /* Check if we have nothing mounted at mp anymore. If so, unset DENTRY_FLAG_MOUNTPOINT.
         * There's no race because MOUNTPOINT is only set while holding mount_lock in write mode. */
        if (!mnt_find_by_mp(mp))
            __atomic_and_fetch(&mp->d_flags, ~DENTRY_FLAG_MOUNTPOINT, __ATOMIC_RELEASE);
        mount->mnt_flags |= MNT_DOOMED;
    }

    write_sequnlock(&mount_lock);
    return ok;
}

static int do_umount_path(struct path *path, int flags)
{
    int err = -EINVAL;
    struct mount *mount = path->mount;

    /* Check if the path given is actually a mountpoint */
    if (path->mount->mnt_root != path->dentry)
        goto out_put_path;

    err = -EBUSY;
    if (!attempt_disconnect(mount))
        goto out_put_path;

    /* Mount was disconnected. No one should hold a reference to one of this mount's dentries after
     * this. */
    path_put(path);

    if (mount->mnt_sb->s_ops->umount)
        mount->mnt_sb->s_ops->umount(mount);

    dentry_shrink_subtree(mount->mnt_root);
    dput(mount->mnt_point);

    WARN_ON(mount->mnt_root->d_ref != 1);

    /* Finally, put our root */
    dput(mount->mnt_root);

    /* Now shutdown the superblock */
    sb_shutdown(mount->mnt_sb);
    kfree_rcu(mount, mnt_rcu);
    return 0;
out_put_path:
    path_put(path);
    return err;
}

int sys_umount2(const char *utarget, int flags)
{
    int err = -EINVAL;
    const char *target;

    if (!is_root_user())
        return -EPERM;

    target = strcpy_from_user(utarget);
    if (!target)
        return -errno;
    if (flags & ~UMOUNT_NOFOLLOW)
        goto out;

    struct path path;
    err = path_openat(AT_FDCWD, target,
                      LOOKUP_MUST_BE_DIR | (flags & UMOUNT_NOFOLLOW ? LOOKUP_NOFOLLOW : 0), &path);
    if (err < 0)
        goto out;

    err = do_umount_path(&path, flags);
out:
    free((void *) target);
    return err;
}

static void *mounts_seq_start(struct seq_file *m, off_t *off)
{
    read_seqlock_excl(&mount_lock);
    return seq_list_start(&mount_list, *off);
}

static void *mounts_seq_next(struct seq_file *m, void *ptr, off_t *off)
{
    return seq_list_next(ptr, &mount_list, off);
}

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

static void mounts_print_flags(struct seq_file *m, struct mount *mnt)
{
    unsigned int flags = READ_ONCE(mnt->mnt_flags);
    unsigned int i;
    static const struct
    {
        unsigned int flag;
        const char *name;
    } mnt_flags[] = {
        {MNT_NOATIME, "noatime"},
        {MNT_STRICTATIME, "strictatime"},
        {MNT_NODIRATIME, "nodiratime"},
    };

    seq_puts(m, mnt_rdonly(mnt) ? "ro" : "rw");

    for (i = 0; i < ARRAY_SIZE(mnt_flags); i++)
    {
        if (flags & mnt_flags[i].flag)
        {
            seq_putc(m, ',');
            seq_puts(m, mnt_flags[i].name);
        }
    }

    if (!(flags & (MNT_NOATIME | MNT_STRICTATIME | MNT_NODIRATIME)))
        seq_puts(m, ",relatime");
}

static int mounts_seq_show(struct seq_file *m, void *ptr)
{
    struct mount *mnt = list_entry(ptr, struct mount, mnt_namespace_node);
    struct path p = {.dentry = mnt->mnt_root, .mount = mnt};
    int err;

    seq_printf(m, "%s ", mnt->mnt_devname);
    err = seq_d_path_under_root(m, &p, NULL);
    if (err)
        return err;
    seq_printf(m, " %s ", mnt->mnt_sb->s_type->name);
    mounts_print_flags(m, mnt);
    seq_printf(m, " 0 0");
    seq_putc(m, '\n');
    return 0;
}

static void mounts_seq_stop(struct seq_file *m, void *ptr)
{
    read_sequnlock_excl(&mount_lock);
}

static const struct seq_operations mounts_seq_ops = {
    .start = mounts_seq_start,
    .next = mounts_seq_next,
    .show = mounts_seq_show,
    .stop = mounts_seq_stop,
};

static int mounts_open(struct file *filp)
{
    return seq_open(filp, &mounts_seq_ops);
}

const struct proc_file_ops mounts_proc_ops = {
    .open = mounts_open,
    .release = seq_release,
    .read_iter = seq_read_iter,
};

static __init void mount_init(void)
{
    for (int i = 0; i < MT_HASH_SIZE; i++)
    {
        INIT_LIST_HEAD(&mount_hashtable[i]);
        INIT_LIST_HEAD(&mp_hashtable[i]);
    }

    procfs_add_entry("mounts", 0444, NULL, &mounts_proc_ops);
}
