/*
 * Copyright (c) 2024 - 2025 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#define DEFINE_CURRENT
#include <ctype.h>

#include <onyx/fs_mount.h>
#include <onyx/libfs.h>
#include <onyx/mm/slab.h>
#include <onyx/proc.h>
#include <onyx/process.h>
#include <onyx/rculist.h>
#include <onyx/rcupdate.h>
#include <onyx/seq_file.h>
#include <onyx/seqlock.h>
#include <onyx/tty.h>

#include "proc.h"

static void proc_set_owner(struct procfs_inode *pfi, struct process *task)
{
    read_lock(&task->cred.lock);
    pfi->pfi_inode.i_uid = task->cred.euid;
    pfi->pfi_inode.i_gid = task->cred.egid;
    read_unlock(&task->cred.lock);
}

struct pid_attr
{
    const char *name;
    mode_t mode;
    const struct proc_file_ops *ops;
    const struct inode_operations *iops;
    const struct file_ops *fops;
    const struct dentry_operations *dops;
};

struct process *get_inode_task(struct procfs_inode *ino)
{
    struct process *task;
    rcu_read_lock();
    task = ino->owner->proc;
    if (!task || !process_get_unless_dead(task))
        task = NULL;
    rcu_read_unlock();
    return task;
}

static int proc_comm_show(struct seq_file *m, void *v)
{
    struct procfs_inode *ino = m->private;
    struct process *task = get_inode_task(ino);
    if (!task)
        return -ESRCH;
    seq_puts(m, task->comm);
    seq_putc(m, '\n');
    process_put(task);
    return 0;
}

static int proc_comm_open(struct file *filp)
{
    return single_open(filp, proc_comm_show, filp->f_ino);
}

static const struct proc_file_ops proc_comm_ops = {
    .open = proc_comm_open,
    .read_iter = seq_read_iter,
    .release = seq_release,
};

static char task_state(struct process *task)
{
    /* TODO: This might be incorrect if the thread is exiting. The kernel has a bunch of these
     * problems already. The thread's lifetime should be tied to process (and eventually merged into
     * struct task_struct) */
    struct thread *thread = task->thr;
    if (test_task_flag(task, PROCESS_ZOMBIE))
        return 'Z';
    if (test_task_flag(task, PROCESS_DEAD))
        return 'X';

    switch (thread->status)
    {
        case THREAD_RUNNABLE:
            return 'R';
        case THREAD_INTERRUPTIBLE:
            return 'S';
        case THREAD_UNINTERRUPTIBLE:
            return 'D';
        case THREAD_STOPPED:
            return 'T';
    }

    WARN_ON_ONCE(1);
    return '?';
}

static int proc_pid_stat_show(struct seq_file *m, void *v)
{
    unsigned long minflt, majflt, cminflt, cmajflt;
    struct procfs_inode *ino = m->private;
    struct signal_struct *sig;
    struct process *task;
    struct mm_address_space *mm;
    unsigned int seq;
    hrtime_t utime, stime, cutime, cstime;
    char state;
    unsigned long vsize, rss, rsslim;
    unsigned long startcode, endcode, startstack;
    unsigned long kstkesp, kstkeip;
    unsigned int pending, blocked, ignored, catched;
    unsigned long wchan;
    unsigned long startdata, enddata;
    unsigned long start_brk;
    unsigned long arg_start, arg_end;
    unsigned long env_start, env_end;
    unsigned int exit_code;
    pid_t ppid;
    int tty_num, tty_pgrp;
    bool whole;

    task = get_inode_task(ino);
    if (!task)
        return -ESRCH;

    rcu_read_lock();
    ppid = task_parent(task) ? task_parent(task)->pid_ : 0;
    whole = thread_group_leader(task);
    state = task_state(task);

    sig = task->sig;
    if (sig->ctty)
    {
        tty_num = (int) sig->ctty->cdev;
        tty_pgrp = pid_nr(rcu_dereference(sig->ctty->pgrp));
    }
    else
    {
        tty_num = 0;
        tty_pgrp = 0;
    }

    exit_code = task->exit_code;

    seq = 0;
    do
    {
        read_seqbegin_or_lock(&sig->stats_lock, &seq);
        minflt = task->minflt;
        majflt = task->majflt;
        cminflt = sig->cminflt;
        cmajflt = sig->cmajflt;
        utime = task->thr->cputime_info.user_time;
        stime = task->thr->cputime_info.system_time;
        cutime = sig->cutime;
        cstime = sig->cstime;

        if (whole)
        {
            struct process *t;
            minflt += sig->minflt;
            majflt += sig->majflt;
            utime += sig->utime;
            stime += sig->stime;

            for_each_thread (task, t)
            {
                if (t == task)
                    continue;
                minflt += t->minflt;
                majflt += t->majflt;
                utime += t->thr->cputime_info.user_time;
                stime += t->thr->cputime_info.system_time;
            }
        }

        if (read_seqretry(&sig->stats_lock, seq))
        {
            seq = 1;
            continue;
        }

        done_seqretry(&sig->stats_lock, seq);
        break;
    } while (1);

    rsslim = READ_ONCE(task->sig->rlimits[RLIMIT_RSS].rlim_cur);
    /* TODO */
    startcode = endcode = kstkeip = kstkesp = startdata = enddata = 0;
    wchan = task->thr->status != THREAD_RUNNABLE;

    mm = get_remote_mm(task);
    /* Note: We put the mm _after_ we unlock RCU, because mmput may very well sleep */
    if (!mm)
    {
        vsize = 0;
        rss = 0;
        start_brk = arg_start = arg_end = 0;
        startstack = 0;
    }
    else
    {
        vsize = mm->virtual_memory_size;
        rss = mm->resident_set_size >> PAGE_SHIFT;
        startstack = mm->stack_start;
        /* More TODO */
        start_brk = 0;
        arg_start = mm->arg_start;
        arg_end = mm->arg_end;
    }

    /* And more...*/
    env_start = env_end = 0;

    pending = READ_ONCE(task->sigqueue.pending.__bits[0]);
    blocked = READ_ONCE(task->sigmask.__bits[0]);

    /* TODO: More todo (counting SIG_IGN and !SIG_DFL...)*/
    ignored = 0;
    catched = 0;

    /* TODO: 0 0 for priority, nice. 0 0 for itrealvalue, starttime. 0 0 for
     * nswap, cnswap. 0 0 0 0 0 for (40 - 44 in the manpage). */
    seq_printf(m,
               "%d (%s) %c %d %d %d %d %d %u %lu %lu %lu %lu %lu %lu %lu %lu 0 0 %lu 0 0 %lu %lu "
               "%lu %lu %lu %lu %lu %lu %u %u %u %u %lu 0 0 %d %d 0 0 0 0 0 %lu %lu %lu %lu %lu "
               "%lu %lu %d\n",
               task->pid_, task->comm, state, ppid, pid_nr(task_pgrp(task)),
               pid_nr(task_session(task)), tty_num, tty_pgrp, (unsigned int) task->flags, minflt,
               cminflt, majflt, cmajflt, utime / NS_PER_MS, stime / NS_PER_MS, cutime / NS_PER_MS,
               cstime / NS_PER_MS, (unsigned long) READ_ONCE(sig->nr_threads), vsize, rss, rsslim,
               startcode, endcode, startstack, kstkesp, kstkeip, pending, blocked, ignored, catched,
               wchan, SIGCHLD, task->thr->cpu, startdata, enddata, start_brk, arg_start, arg_end,
               env_start, env_end, exit_code);

    rcu_read_unlock();
    if (mm)
        mmput(mm);
    process_put(task);
    return 0;
}

static int proc_pid_stat_open(struct file *filp)
{
    return single_open(filp, proc_pid_stat_show, filp->f_ino);
}

static const struct proc_file_ops proc_stat_ops = {
    .open = proc_pid_stat_open,
    .read_iter = seq_read_iter,
    .release = seq_release,
};

static int proc_statm_show(struct seq_file *m, void *ptr)
{
    struct process *task;
    struct mm_address_space *mm;

    task = get_inode_task((struct procfs_inode *) m->private);
    if (!task)
        return -ESRCH;
    mm = get_remote_mm(task);
    if (!mm)
    {
        /* All zeros. */
        seq_printf(m, "0 0 0 0 0 0 0\n");
        goto out_nomm;
    }

    /* Various TODO:s here. Resident shared pages isn't implemented, text pages isn't implemented,
     * data + stack pages isn't implemented. Pls fix. */
    seq_printf(m, "%lu %lu %lu 0 0 0 0\n", READ_ONCE(mm->virtual_memory_size) / 1024,
               READ_ONCE(mm->resident_set_size) / 1024, 0UL);

out_nomm:
    process_put(task);
    return 0;
}

static int proc_statm_open(struct file *filp)
{
    return single_open(filp, proc_statm_show, filp->f_ino);
}

static const struct proc_file_ops proc_statm_ops = {
    .open = proc_statm_open,
    .read_iter = seq_read_iter,
    .release = seq_release,
};

struct file *fdget_remote(struct process *task, unsigned int fd);
bool fdexists_remote(struct process *task, unsigned int fd);
struct file *fdget_remote_next(struct process *task, unsigned int fd, int *out);

static int instantiate(struct dentry *dir, struct dentry *dentry, struct process *task,
                       void (*instantiate)(struct procfs_entry *pfe, void *data), void *data)
{
    struct procfs_entry *new;
    struct procfs_inode *pid_ino;
    struct procfs_inode *inode;
    new = kmalloc(sizeof(*new), GFP_KERNEL);
    if (!new)
        goto err;

    instantiate(new, data);
    inode = (struct procfs_inode *) proc_create_inode(dir->d_inode->i_sb, new);
    if (!inode)
        goto err_free;

    pid_ino = (struct procfs_inode *) dir->d_inode;

    inode->owner = pid_ino->owner;
    get_pid(inode->owner);

    if (new->fops)
        inode->pfi_inode.i_fops = (struct file_ops *) new->fops;
    if (new->dops)
        dentry->d_ops = new->dops;
    proc_set_owner(inode, task);
    d_finish_lookup(dentry, &inode->pfi_inode);
    return 0;
err_free:
    kfree(new);
err:
    return -ENOMEM;
}

struct fd_info
{
    const char *name;
};

static char *proc_fd_readlink(struct dentry *dentry)
{
    /* TODO: Don't do this with PATH_MAX... */
    struct process *task;
    struct file *real;
    int fd;
    char *path, *buf;

    buf = ERR_PTR(-ESRCH);
    fd = str_to_int(dentry->d_name);
    task = get_inode_task((struct procfs_inode *) dentry->d_inode);
    if (!task)
        return ERR_PTR(-ESRCH);
    real = fdget_remote(task, fd);
    if (!real)
        goto err;
    /* XXX: ugh */
    if (!real->f_path.mount)
    {
        buf = ERR_PTR(-ENOENT);
        goto err2;
    }

    buf = kmalloc(PATH_MAX, GFP_KERNEL);
    if (!buf)
    {
        buf = ERR_PTR(-ENOMEM);
        goto err2;
    }

    path = d_path(&real->f_path, buf, PATH_MAX);
    if (IS_ERR(path))
    {
        kfree(buf);
        goto err2;
    }

    memmove(buf, path, strlen(path) + 1);
err2:
    fd_put(real);
err:
    process_put(task);
    return buf;
}

static int proc_fd_magic_jump(struct dentry *dentry, struct inode *inode,
                              struct nameidata *nameidata)
{
    struct procfs_inode *d_ino;
    struct process *task;
    struct file *filp;
    int fd = str_to_int(dentry->d_name);

    d_ino = (struct procfs_inode *) dentry->d_inode;
    task = get_inode_task(d_ino);
    if (!task)
        return -ESRCH;

    filp = fdget_remote(task, fd);
    process_put(task);
    if (!filp)
        return -EBADF;

    /* Ugh... hack for files without mount, show nothing */
    if (!filp->f_path.mount)
    {
        fd_put(filp);
        return -ENOENT;
    }

    path_get(&filp->f_path);
    namei_jump(nameidata, &filp->f_path);
    fd_put(filp);
    return 0;
}

static const struct inode_operations proc_fd_iops = {
    .readlink = proc_fd_readlink,
    .magic_jump = proc_fd_magic_jump,
};

static int proc_fd_revalidate(struct dentry *dentry, unsigned int flags)
{
    int fd;
    struct procfs_inode *d_ino;
    struct process *task;
    int ret;

    if (d_is_negative(dentry))
    {
        /* Unfortunately, we have no easy way of revalidating negative dentries (we don't have a
         * reference to the task struct). As such, always assume they're invalid. We probably don't
         * have many ENOENTs in these cases anyway. (Use the parent dentry's inode?) */
        return 0;
    }

    fd = str_to_int(dentry->d_name);
    d_ino = (struct procfs_inode *) dentry->d_inode;
    task = get_inode_task(d_ino);
    if (!task)
        return 0;

    ret = fdexists_remote(task, fd);
    process_put(task);
    return ret;
}

const struct dentry_operations proc_fd_dops = {
    .d_revalidate = proc_fd_revalidate,
};

static void fd_instantiate(struct procfs_entry *new, void *data)
{
    struct fd_info *info = data;
    procfs_init_entry(new, info->name, 0700 | S_IFLNK, NULL, &proc_noop);
    new->iops = &proc_fd_iops;
    new->dops = &proc_fd_dops;
}

static int proc_fd_open(struct dentry *dir, const char *name, struct dentry *dentry)
{
    struct procfs_inode *d_ino;
    struct process *task;
    struct file *filp;
    struct fd_info info;
    int fd;
    int err = -ENOENT;

    d_ino = (struct procfs_inode *) dir->d_inode;
    fd = str_to_int(name);
    if (fd == -1)
        return -ENOENT;

    task = get_inode_task(d_ino);
    if (!task)
        return -ESRCH;

    err = -ENOENT;
    filp = fdget_remote(task, fd);
    if (!filp)
        goto out;
    fd_put(filp);
    info.name = name;
    err = instantiate(dir, dentry, task, fd_instantiate, &info);
out:
    process_put(task);
    return err;
}

static const struct inode_operations proc_fd_operations = {
    .open = proc_fd_open,
};

static off_t proc_fd_getdirent(struct dirent *buf, off_t off, struct file *file)
{
    struct procfs_inode *ino = (struct procfs_inode *) file->f_ino;
    struct process *proc;
    off_t ret = 0;
    int fd, out;
    struct file *filp;

    proc = get_inode_task(ino);
    if (!proc)
        return -ESRCH;
    if (off < 2)
    {
        ret = libfs_put_dots(buf, off, file->f_dentry);
        goto out;
    }

    fd = off - 2;
    filp = fdget_remote_next(proc, fd, &out);
    if (filp)
    {
        char name[16];
        sprintf(name, "%d", out);
        put_dir(name, out + 2, 0, DT_LNK, buf);
        ret = out + 2 + 1;
        fd_put(filp);
    }

out:
    process_put(proc);
    return ret;
}

static const struct file_ops proc_fd_fops = {
    .getdirent = proc_fd_getdirent,
};

static char *proc_exe_readlink(struct dentry *dentry)
{
    /* TODO: Don't do this with PATH_MAX... */
    struct process *task;
    struct file *real;
    char *path, *buf;

    buf = ERR_PTR(-ESRCH);
    task = get_inode_task((struct procfs_inode *) dentry->d_inode);
    if (!task)
        return ERR_PTR(-ESRCH);
    real = get_task_exe(task);
    if (!real)
        goto err;
    /* XXX: ugh */
    if (!real->f_path.mount)
    {
        buf = ERR_PTR(-ENOENT);
        goto err2;
    }

    buf = kmalloc(PATH_MAX, GFP_KERNEL);
    if (!buf)
    {
        buf = ERR_PTR(-ENOMEM);
        goto err2;
    }

    path = d_path(&real->f_path, buf, PATH_MAX);
    if (IS_ERR(path))
    {
        kfree(buf);
        goto err2;
    }

    memmove(buf, path, strlen(path) + 1);
err2:
    fd_put(real);
err:
    process_put(task);
    return buf;
}

static int proc_exe_magic_jump(struct dentry *dentry, struct inode *inode,
                               struct nameidata *nameidata)
{
    struct procfs_inode *d_ino;
    struct process *task;
    struct file *filp;

    d_ino = (struct procfs_inode *) dentry->d_inode;
    task = get_inode_task(d_ino);
    if (!task)
        return -ESRCH;

    filp = get_task_exe(task);
    process_put(task);
    if (!filp)
        return -EBADF;

    /* Ugh... hack for files without mount, show nothing */
    if (!filp->f_path.mount)
    {
        fd_put(filp);
        return -ENOENT;
    }

    path_get(&filp->f_path);
    namei_jump(nameidata, &filp->f_path);
    fd_put(filp);
    return 0;
}

static const struct inode_operations proc_exe_iops = {
    .readlink = proc_exe_readlink,
    .magic_jump = proc_exe_magic_jump,
};

extern const struct proc_file_ops proc_maps_ops;
extern const struct proc_file_ops mounts_proc_ops;

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

// clang-format off
static const struct pid_attr pid_attrs[] = {
    {"comm", S_IFREG | 0444, &proc_comm_ops},
    {"stat", S_IFREG | 0444, &proc_stat_ops},
    {"statm", S_IFREG | 0444, &proc_statm_ops},
    {"fd", S_IFDIR | 0444, &proc_noop, &proc_fd_operations, &proc_fd_fops},
    {"maps",  S_IFREG | 0400, &proc_maps_ops},
    {"mounts", S_IFREG | 0400, &mounts_proc_ops},
    {"exe", S_IFLNK | 0777, &proc_noop, &proc_exe_iops},
};

// clang-format on

#define NR_PID_ATTRS ARRAY_SIZE(pid_attrs)

static int pid_attr_instantiate(const struct pid_attr *attr, struct dentry *dir,
                                struct dentry *dentry)
{
    struct procfs_entry *new;
    struct procfs_inode *pid_ino;
    struct procfs_inode *inode;
    struct process *task;
    int err = -ENOMEM;
    new = kmalloc(sizeof(*new), GFP_KERNEL);
    if (!new)
        goto err;
    pid_ino = (struct procfs_inode *) dir->d_inode;
    task = get_inode_task(pid_ino);
    if (!task)
    {
        err = -ESRCH;
        goto err_free;
    }

    procfs_init_entry(new, attr->name, attr->mode, NULL, attr->ops);

    inode = (struct procfs_inode *) proc_create_inode(dir->d_inode->i_sb, new);
    if (!inode)
        goto err_put;

    pid_ino = (struct procfs_inode *) dir->d_inode;

    if (attr->iops)
        inode->pfi_inode.i_op = attr->iops;
    if (attr->dops)
        dentry->d_ops = attr->dops;
    if (attr->fops)
        inode->pfi_inode.i_fops = (struct file_ops *) attr->fops;

    inode->owner = pid_ino->owner;
    proc_set_owner(inode, task);
    get_pid(inode->owner);
    process_put(task);
    d_finish_lookup(dentry, &inode->pfi_inode);
    return 0;
err_put:
    process_put(task);
err_free:
    kfree(new);
err:
    return err;
}

static int proc_pid_open_attrs(struct dentry *dir, const char *name, struct dentry *dentry)
{
    const struct pid_attr *attr = NULL;

    for (unsigned int i = 0; i < NR_PID_ATTRS; i++)
    {
        if (!strcmp(pid_attrs[i].name, name))
        {
            attr = &pid_attrs[i];
            break;
        }
    }

    if (!attr)
        return -ENOENT;
    return pid_attr_instantiate(attr, dir, dentry);
}

off_t pid_attrs_getdirent(struct dirent *buf, off_t off, struct file *file)
{
    unsigned int i;
    const struct pid_attr *attr;

    if (off < 2)
        return libfs_put_dots(buf, off, file->f_dentry);

    i = off - 2;
    if (i >= NR_PID_ATTRS)
        return 0;

    attr = &pid_attrs[i];
    put_dir(attr->name, off, 0, IFTODT(attr->mode), buf);
    return off + 1;
}

static const struct proc_file_ops pid_ops = {};
static const struct inode_operations pid_ino_ops = {
    .stat = proc_stat,
    .open = proc_pid_open_attrs,
};

static int proc_pid_revalidate(struct dentry *dentry, unsigned int flags)
{
    int err = 0;
    rcu_read_lock();
    struct procfs_inode *ino = (struct procfs_inode *) dentry->d_inode;
    if (READ_ONCE(ino->owner->proc))
        err = 1;

    rcu_read_unlock();
    return err;
}

static int proc_pid_revalidate_negative(struct dentry *dentry, unsigned int flags)
{
    /* Check if there's a task with this pid */
    pid_t pid = str_to_int(dentry->d_name);
    CHECK(pid != -1);
    return get_process_from_pid_noref(pid) == NULL;
}

static const struct dentry_operations pid_dentry_ops = {
    .d_revalidate = proc_pid_revalidate,
};

static const struct dentry_operations pid_dentry_negative_ops = {
    .d_revalidate = proc_pid_revalidate_negative,
};

static const struct file_ops pid_fops = {
    .getdirent = pid_attrs_getdirent,
};

static int proc_create_pid(struct dentry *dir, const char *name, struct process *task,
                           struct dentry *dentry)
{
    struct procfs_inode *inode;
    struct procfs_entry *new;
    struct pid *pid;
    int err = -ENOMEM;

    pid = task->pid_struct;
    get_pid(pid);
    new = kmalloc(sizeof(*new), GFP_KERNEL);
    if (!new)
        goto err;

    procfs_init_entry(new, name, 0555 | S_IFDIR, NULL, &pid_ops);
    new->iops = &pid_ino_ops;
    new->fops = &pid_fops;

    inode = (struct procfs_inode *) proc_create_inode(dir->d_inode->i_sb, new);
    if (!inode)
        goto err_free;

    inode->owner = pid;
    proc_set_owner(inode, task);
    d_finish_lookup(dentry, &inode->pfi_inode);
    dentry->d_ops = &pid_dentry_ops;
    return 0;
err_free:
    kfree(new);
err:
    put_pid(pid);
    return err;
}

int proc_pid_open(struct dentry *dir, const char *name, struct dentry *dentry)
{
    struct process *task;
    int err;
    pid_t pid = str_to_int(name);
    if (pid == -1)
        return -EINVAL;

    rcu_read_lock();
    task = get_process_from_pid(pid);
    rcu_read_unlock();
    if (!task)
    {
        d_complete_negative(dentry);
        dentry->d_ops = &pid_dentry_negative_ops;
        return -ENOENT;
    }

    err = proc_create_pid(dir, name, task, dentry);
    /* proc_create_pid does not consume task's reference, only takes a ref on its pid */
    process_put(task);
    return err;
}
