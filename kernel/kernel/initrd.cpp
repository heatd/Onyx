/*
 * Copyright (c) 2016 - 2025 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <assert.h>
#include <errno.h>
#include <libgen.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>

#include <onyx/compression.h>
#include <onyx/dentry.h>
#include <onyx/dev.h>
#include <onyx/file.h>
#include <onyx/initrd.h>
#include <onyx/memstream.h>
#include <onyx/namei.h>
#include <onyx/panic.h>
#include <onyx/string_parsing.h>
#include <onyx/tmpfs.h>
#include <onyx/vector.h>
#include <onyx/vfs.h>

#include <onyx/pair.hpp>

bool is_tar(void *initrd)
{
    tar_header_t *header = (tar_header_t *) initrd;
    return !memcmp(header->magic, "ustar ", 5);
}

unsigned int parse_perms_from_tar(tar_header_t *entry)
{
    return parser::parse_number_from_string<unsigned int>({entry->mode, strlen(entry->mode)})
        .unwrap();
}

void tar_handle_entry(tar_header_t *entry, onx::stream &str)
{
    char *full_filename;
    if (memcmp(entry->magic, "ustar ", 5))
        panic("Tar entry with invalid magic value");
    auto filenamelen = strnlen(entry->filename, 100);
    size_t len;

    if (entry->prefix[0] != '\0')
    {
        auto prefixlen = strnlen(entry->prefix, 155);
        full_filename = (char *) malloc(prefixlen + filenamelen + 2); // Additional char for /
        memcpy(full_filename, entry->prefix, prefixlen);
        full_filename[prefixlen] = '/';
        memcpy(full_filename + prefixlen + 1, entry->filename, filenamelen);
        full_filename[prefixlen + filenamelen + 1] = '\0';
        len = prefixlen + filenamelen + 1;
    }
    else
    {
        full_filename = (char *) memdup(entry->filename, filenamelen + 1);
        full_filename[filenamelen] = '\0';
        len = filenamelen;
    }

    // Trim trailing slashes
    while (len > 0 && full_filename[len - 1] == '/')
        len--;
    full_filename[len] = '\0';

    auto last_slash = strrchr(full_filename, '/');

    if (last_slash)
    {
        auto slash_ptr = strchr(full_filename, '/');
        while (slash_ptr != last_slash)
        {
        retry:
            *slash_ptr = '\0';
            auto ex = vfs_open(AT_FDCWD, full_filename, O_RDONLY | O_DIRECTORY, 0);
            if (ex.has_error())
            {
                if (ex.error() != -ENOENT)
                    panic("initrd: failed to unpack: vfs_open returned (unexpected) %d\n",
                          ex.error());

                auto ex2 = mkdir_vfs(full_filename, 0755, AT_FDCWD);
                if (ex2.has_error())
                {
                    perror("mkdir");
                    panic("Error loading initrd");
                }

                dput(ex2.value());
                fd_put(ex.value());
                goto retry;
            }

            fd_put(ex.value());
            *slash_ptr = '/';
            slash_ptr = strchr(slash_ptr + 1, '/');
        }
    }
    /* After creat/opening the directories, create it and populate it */
    unsigned int perms = parse_perms_from_tar(entry);

    if (entry->typeflag == TAR_TYPE_FILE)
    {
        struct file *filp;
        auto ex = vfs_open(AT_FDCWD, full_filename, O_RDWR | O_CREAT, perms);
        if (ex.has_error())
            panic("Could not create file from initrd - errno %d", ex.error());

        filp = ex.value();
        size_t size = tar_get_size(entry->size);
        str.splice(size, filp).unwrap();
        fd_put(filp);
    }
    else if (entry->typeflag == TAR_TYPE_DIR)
    {
        auto dent = mkdir_vfs(full_filename, perms, AT_FDCWD).unwrap();
        dput(dent);
    }
    else if (entry->typeflag == TAR_TYPE_SYMLNK)
    {
        char *buffer = (char *) entry->linkname;
        int st = symlink_vfs(full_filename, buffer, AT_FDCWD);
        CHECK(st == 0);
    }
}

expected<unique_ptr<compression::decompress_bytestream>, int> try_decompress(
    cul::slice<unsigned char> src)
{
    auto compstream = compression::create_decompression_stream(src).unwrap();
    auto bstr = make_unique<compression::decompress_bytestream>(cul::move(compstream), src);

    // Default to the compressed initrd's size
    // Use 1MB as the minimum, 128MB as the maximum
    auto buf_len = src.size_bytes();
    buf_len = cul::max(buf_len, 0x100000UL);
    buf_len = cul::min(buf_len, 0x8000000UL);
    assert(bstr->init(buf_len) == true);

    return cul::move(bstr);
}

void tar_unpack(onx::stream &str)
{
    while (true)
    {
        tar_header_t hdr;
        auto ex = str.read(cul::slice<unsigned char>{(unsigned char *) &hdr, sizeof(hdr)}).unwrap();
        if (ex == 0)
            break;
        if (hdr.filename[0] == '\0')
            break;
        str.skip(12);
        const auto raw_size = tar_get_size(hdr.size);
        const size_t size = cul::align_up2(raw_size, 512UL);
        tar_handle_entry(&hdr, str);
        // printk("Skipping %zu (%s)\n", size, hdr.size);
        ex = str.skip(size - raw_size).unwrap();
    }
}

void init_initrd(void *initrd, size_t length)
{
    printf("Found an Initrd at %p\n", initrd);

    /* Mount a new instance of a tmpfs at / */
    tmpfs_kern_mount("/");
    const cul::slice<unsigned char> initrd_src{(unsigned char *) initrd, length};

    auto str = make_unique<onx::memstream>(initrd_src).cast<onx::stream>();
    assert(str.get() != nullptr);

    if (!is_tar(initrd))
    {
        printf("initrd: Given initrd is not a TAR - trying to decompress\n");
        str = try_decompress(initrd_src).unwrap();
    }

    tar_unpack(*str);
}
