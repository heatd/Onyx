/*
 * Copyright (c) 2021 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 */

#include <errno.h>

#include <onyx/dentry.h>
#include <onyx/file.h>
#include <onyx/handle.h>
#include <onyx/vfs.h>

#include <onyx/expected.hpp>

namespace onx
{

namespace handle
{

#define VALID_HANDLE_OPEN_FLAGS (ONX_HANDLE_CLOEXEC)

using handle_opener = expected<file *, int> (*)(unsigned int, unsigned long, int);

#define HANDLE_OPENER(name) extern expected<file *, int> name(unsigned int, unsigned long, int);

HANDLE_OPENER(process_handle_opener);

handle_opener handle_open_handlers[] = {process_handle_opener};

int handle_open_flags_to_open(int handle_open_fl)
{
    int fl = 0;
    if (handle_open_fl & ONX_HANDLE_CLOEXEC)
        fl |= O_CLOEXEC;

    return fl;
}

handleable *handle_from_inode(const inode *ino)
{
    return (handleable *) ino->i_helper;
}

handleable *handle_from_file(const file *f)
{
    return handle_from_inode(f->f_ino);
}

void handle_file_close(struct inode *ino)
{
    handle_from_inode(ino)->handle_unref();
}

struct file_ops handle_ops = {.read = nullptr, .write = nullptr, .close = handle_file_close};

file *handle_inode_to_file(inode *ino)
{
    auto f = inode_to_file(ino);
    if (!f)
        return nullptr;

    auto dent = dentry_create("<handle>", ino, nullptr);
    if (!dent)
    {
        fd_put(f);
        return nullptr;
    }

    f->f_dentry = dent;
    return f;
}

file *create_file(handleable *obj)
{
    inode *ino = inode_create(false);
    if (!ino)
        return nullptr;

    ino->i_fops = &handle_ops;
    ino->i_type = VFS_TYPE_CHAR_DEVICE;
    ino->i_helper = obj;

    auto file = handle_inode_to_file(ino);

    if (!file)
        inode_unref(ino);

    return file;
}

bool file_is_handlefd(file *f)
{
    return f->f_ino->i_fops == &handle_ops;
}

} // namespace handle

} // namespace onx

int sys_onx_handle_open(unsigned int resource_type, unsigned long id, int flags)
{
    if (flags & ~VALID_HANDLE_OPEN_FLAGS)
        return -EINVAL;

    if (resource_type >=
        (sizeof(onx::handle::handle_open_handlers) / sizeof(onx::handle::handle_open_handlers[0])))
        return -EINVAL;

    auto handle = onx::handle::handle_open_handlers[resource_type](resource_type, id, flags);

    if (handle.has_error())
        return handle.error();

    int fd = open_with_vnode(handle.value(), onx::handle::handle_open_flags_to_open(flags));

    // This fd_put is unconditional since open_with_vnode increments the ref on success
    fd_put(handle.value());

    return fd;
}

ssize_t sys_onx_handle_query(int handle, void *buffer, ssize_t len, unsigned long what,
                             size_t *howmany, void *arg)
{
    if (len < 0)
        return -EINVAL;

    auto_file f = get_file_description(handle);

    if (!f)
        return -errno;

    /* Test if this is a handle fd before going any further */

    if (!onx::handle::file_is_handlefd(f.get_file()))
        return -EBADF;

    auto handleable = onx::handle::handle_from_file(f.get_file());

    size_t howmany_kernel = 0xabababab;

    auto st = handleable->query(buffer, len, what, &howmany_kernel, arg);

    if (howmany != nullptr)
    {
        if (copy_to_user(howmany, &howmany_kernel, sizeof(size_t)) < 0)
            return -EFAULT;
    }

    return st;
}
