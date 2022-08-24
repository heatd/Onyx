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

#include <onyx/compression.h>
#include <onyx/dev.h>
#include <onyx/initrd.h>
#include <onyx/panic.h>
#include <onyx/string_parsing.h>
#include <onyx/tmpfs.h>
#include <onyx/vector.h>
#include <onyx/vfs.h>

#include <onyx/pair.hpp>

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
        auto len = strnlen(header->filename, 100);
        if (header->filename[len - 1] == '/')
            header->filename[len - 1] = 0;
        size_t size = tar_get_size(header->size);
        headers.push_back(header);
        address += ((size / 512) + 1) * 512;
        if (size % 512)
            address += 512;
    }
    return i;
}

unsigned int parse_perms_from_tar(tar_header_t *entry)
{
    return parser::parse_number_from_string<unsigned int>({entry->mode, strlen(entry->mode)})
        .unwrap();
}

void initrd_mount()
{
    for (auto entry : headers)
    {
        char *saveptr;
        auto len = strnlen(entry->filename, 100);

#if 0
        cul::string name;

        if (entry->prefix[0])
        {
            name = cul::string{entry->prefix, strnlen(entry->prefix, 131)};
            assert(name);
        }

        if (!name.append({entry->filename, len}))
            panic("oom initrd");
#endif
        char *filename = (char *) memdup(entry->filename, len + 1);
        filename[len] = '\0';
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
                    if (!(node = mkdir_vfs(filename, 0755, node->f_dentry)))
                    {
                        perror("mkdir");
                        panic("Error loading initrd");
                    }
                }
                filename = strtok_r(nullptr, "/", &saveptr);
            }
        }
        /* After creat/opening the directories, create it and populate it */
        strlcpy(old, entry->filename, len + 1);
        filename = old;
        filename = basename(filename);
        unsigned int perms = parse_perms_from_tar(entry);

        if (entry->typeflag == TAR_TYPE_FILE)
        {
            struct file *file = creat_vfs(node->f_dentry, filename, perms);
            if (!file)
            {
                panic("Could not create file from initrd - errno %d", errno);
            }

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
            struct file *file = mkdir_vfs(filename, perms, node->f_dentry);
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

bool is_tar(void *initrd)
{
    tar_header_t *header = (tar_header_t *) initrd;
    return !memcmp(header->magic, "ustar ", 6);
}

struct decompression_data
{
    void *out;
    size_t len;
    size_t capacity;
};

// Note: This is horrible and not ideal... We should stream it.

expected<decompression_data, int> try_decompress(cul::slice<unsigned char> src)
{
    // Let's attempt to start decompression with 6x the memory
    auto buflen = src.size_bytes() * 10;

    auto t0 = clocksource_get_time();

    while (true)
    {
        void *ptr = vmalloc(vm_size_to_pages(buflen), VM_TYPE_REGULAR, VM_WRITE | VM_READ);
        if (!ptr)
            return unexpected<int>{-ENOMEM};

        auto ex = compression::decompress(ptr, buflen, src);
        if (ex.has_error())
        {
            if (ex.error() == -ENOSPC)
            {
                vfree(ptr, vm_size_to_pages(buflen));
                buflen += 0x100000;
                continue;
            }

            printk("initrd: Error decompressing: %d\n", ex.error());
            return unexpected<int>{ex.error()};
        }

        auto t1 = clocksource_get_time();

        printf("initrd: Decompressed %zu bytes in %lu ms\n", ex.value(), (t1 - t0) / NS_PER_MS);

        return decompression_data{ptr, ex.value(), buflen};
    }
}

void init_initrd(void *initrd, size_t length)
{
    bool reclaim_decompress = false;
    size_t reclaim_size = 0;
    printf("Found an Initrd at %p\n", initrd);

    if (!is_tar(initrd))
    {
        printf("initrd: Given initrd is not a TAR - trying to decompress\n");
        auto dec_data =
            try_decompress(cul::slice<unsigned char>{(unsigned char *) initrd, length}).unwrap();

        initrd = dec_data.out;
        length = dec_data.len;
        reclaim_size = dec_data.capacity;
        reclaim_decompress = true;

        if (!is_tar(initrd))
        {
            panic("initrd: Given initrd is not a TAR, even after decompression");
        }
    }

    n_files = tar_parse((uintptr_t) initrd);
    printf("Found %lu files in the Initrd\n", n_files);

    /* Mount a new instance of a tmpfs at / */
    tmpfs_kern_mount("/");

    initrd_mount();

    if (reclaim_decompress)
    {
        vfree(initrd, vm_size_to_pages(reclaim_size));
    }
}
