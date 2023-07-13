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
#include <onyx/file.h>
#include <onyx/initrd.h>
#include <onyx/memstream.h>
#include <onyx/panic.h>
#include <onyx/string_parsing.h>
#include <onyx/tmpfs.h>
#include <onyx/vector.h>
#include <onyx/vfs.h>

#include <onyx/pair.hpp>

bool is_tar(void *initrd)
{
    tar_header_t *header = (tar_header_t *) initrd;
    return !memcmp(header->magic, "ustar ", 6);
}

unsigned int parse_perms_from_tar(tar_header_t *entry)
{
    return parser::parse_number_from_string<unsigned int>({entry->mode, strlen(entry->mode)})
        .unwrap();
}

void tar_handle_entry(tar_header_t *entry, onx::stream &str)
{
    char *saveptr;
    if (memcmp(entry->magic, "ustar ", 6))
        panic("Tar entry with invalid magic value");
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
        auto_file file = creat_vfs(node->f_dentry, filename, perms);
        if (!file)
        {
            panic("Could not create file from initrd - errno %d", errno);
        }

        size_t size = tar_get_size(entry->size);
        str.splice(size, file.get_file()).unwrap();
    }
    else if (entry->typeflag == TAR_TYPE_DIR)
    {
        auto_file file = mkdir_vfs(filename, perms, node->f_dentry);
        if (!file)
            perror("mkdir_vfs");
        assert(file.get_file());
    }
    else if (entry->typeflag == TAR_TYPE_SYMLNK)
    {
        char *buffer = (char *) entry->linkname;
        auto_file file = symlink_vfs(filename, buffer, node->f_dentry);
        assert(file.get_file());
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

    printk("unpacking\n");

    tar_unpack(*str);
}
