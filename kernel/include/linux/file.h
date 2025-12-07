#ifndef _LINUX_FILE_H
#define _LINUX_FILE_H

#include <onyx/file.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/bug.h>

#define get_file(file) (fd_get(file))
#define fput(file) (fd_put(file))

static inline int get_unused_fd_flags(int flags)
{
    WARN_ON(1);
    return -EMFILE;
}

static inline void fd_install(unsigned int fd, struct file *filp)
{
}

static inline void put_unused_fd(unsigned int fd)
{
}

#define file_inode(filp) ((filp)->f_ino)

#endif
