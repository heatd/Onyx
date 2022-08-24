/*
 * Copyright (c) 2016 - 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#include <assert.h>
#include <errno.h>
#include <libgen.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>

#include <onyx/dev.h>
#include <onyx/initrd.h>
#include <onyx/panic.h>
#include <onyx/tmpfs.h>
#include <onyx/vector.h>
#include <onyx/vfs.h>

cul::vector<tar_header_t *> headers;
size_t n_files = 0;
size_t tar_parse(uintptr_t address)
{
    size_t i = 0;

    for (i = 0;; i++)
    {
        tar_header_t *header = (tar_header_t *) address;
        if (header->filename[0] == '\0')
            break;
        /* Remove the trailing slash */
        if (header->filename[strlen(header->filename) - 1] == '/')
            header->filename[strlen(header->filename) - 1] = 0;
        size_t size = tar_get_size(header->size);
        headers.push_back(header);
        address += ((size / 512) + 1) * 512;
        if (size % 512)
            address += 512;
    }
    return i;
}

void initrd_mount()
{
    for (auto entry : headers)
    {
        char *saveptr;
        char *filename = strdup(entry->filename);
        char *old = filename;

        assert(filename != nullptr);

        filename = dirname(filename);

        filename = strtok_r(filename, "/", &saveptr);

        struct file *node = get_fs_root();
        if (*filename != '.' && strlen(filename) != 1)
        {
            while (filename)
            {
                struct file *last = node;
                if (!(node = open_vfs(node, filename)))
                {
                    node = last;
                    if (!(node = mkdir_vfs(filename, 0777, node->f_dentry)))
                    {
                        perror("mkdir");
                        panic("Error loading initrd");
                    }
                }
                filename = strtok_r(nullptr, "/", &saveptr);
            }
        }
        /* After creat/opening the directories, create it and populate it */
        strcpy(old, entry->filename);
        filename = old;
        filename = basename(filename);

        if (entry->typeflag == TAR_TYPE_FILE)
        {
            struct file *file = creat_vfs(node->f_dentry, filename, 0666);
            assert(file != nullptr);

            char *buffer = (char *) entry + 512;
            size_t size = tar_get_size(entry->size);
            ssize_t st = write_vfs(0, size, buffer, file);

            if (st < 0)
            {
                perror("write_vfs");
                assert(st > 0);
            }
        }
        else if (entry->typeflag == TAR_TYPE_DIR)
        {
            struct file *file = mkdir_vfs(filename, 0666, node->f_dentry);
            if (!file)
                perror("mkdir_vfs");
            assert(file != nullptr);
        }
        else if (entry->typeflag == TAR_TYPE_SYMLNK)
        {
            char *buffer = (char *) entry->linkname;
            struct file *file = symlink_vfs(filename, buffer, node->f_dentry);
            assert(file != nullptr);
        }
    }
}

void init_initrd(void *initrd)
{
    printf("Found an Initrd at %p\n", initrd);
    n_files = tar_parse((uintptr_t) initrd);
    printf("Found %lu files in the Initrd\n", n_files);

    /* Mount a new instance of a tmpfs at / */
    tmpfs_kern_mount("/");

    initrd_mount();
}
