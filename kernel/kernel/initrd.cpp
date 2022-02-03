/*
 * Copyright (c) 2016, 2017 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
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
#include <onyx/vfs.h>

tar_header_t *headers[300] = {0};
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
        headers[i] = header;
        address += ((size / 512) + 1) * 512;
        if (size % 512)
            address += 512;
    }
    return i;
}

void initrd_mount(void)
{
    tar_header_t **iter = headers;
    for (size_t i = 0; i < n_files; i++)
    {
        char *saveptr;
        char *filename = strdup(iter[i]->filename);
        char *old = filename;

        assert(filename != NULL);

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
                filename = strtok_r(NULL, "/", &saveptr);
            }
        }
        /* After creat/opening the directories, create it and populate it */
        strcpy(old, iter[i]->filename);
        filename = old;
        filename = basename(filename);

        if (iter[i]->typeflag == TAR_TYPE_FILE)
        {
            struct file *file = creat_vfs(node->f_dentry, filename, 0666);
            assert(file != NULL);

            char *buffer = (char *) iter[i] + 512;
            size_t size = tar_get_size(iter[i]->size);
            ssize_t st = write_vfs(0, size, buffer, file);

            if (st < 0)
            {
                perror("write_vfs");
                assert(st > 0);
            }
        }
        else if (iter[i]->typeflag == TAR_TYPE_DIR)
        {
            struct file *file = mkdir_vfs(filename, 0666, node->f_dentry);
            if (!file)
                perror("mkdir_vfs");
            assert(file != NULL);
        }
        else if (iter[i]->typeflag == TAR_TYPE_SYMLNK)
        {
            char *buffer = (char *) iter[i]->linkname;
            struct file *file = symlink_vfs(filename, buffer, node->f_dentry);
            assert(file != NULL);
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
