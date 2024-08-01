/*
 * Copyright (c) 2017 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <onyx/binfmt.h>
#include <onyx/exec.h>

static struct binfmt *format_list;
void *load_binary(struct binfmt_args *args)
{
    struct binfmt *f = format_list;
    for (; f; f = f->next)
    {
        if (f->is_valid_exec(args->file_signature))
        {
            /* We found the binary, load it */
            return f->callback(args);
        }
    }
    return errno = ENOEXEC, nullptr;
}

int install_binfmt(struct binfmt *format)
{
    if (!format_list)
        format_list = format;
    else
    {
        struct binfmt *f = format_list;
        for (; f->next; f = f->next)
            ;
        f->next = format;
    }
    return 0;
}

void *bin_do_interp(struct binfmt_args *_args)
{
    struct binfmt_args args;
    memcpy(&args, _args, sizeof(struct binfmt_args));

    struct file *file = open_vfs(AT_FDCWD, args.interp_path);
    if (!file)
    {
#if 0
		printk("Could not open %s\n", args.interp_path);
		perror("open_vfs");
#endif
        return nullptr;
    }

    if (!file_is_executable(file))
    {
        errno = EACCES;
        return nullptr;
    }

    if (ssize_t st = read_vfs(0, BINFMT_SIGNATURE_LENGTH, args.file_signature, file); st < 0)
    {
        errno = -st;
        return nullptr;
    }

    args.filename = args.interp_path;
    args.file = file;

    return load_binary(&args);
}
