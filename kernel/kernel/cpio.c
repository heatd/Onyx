/*
 * Copyright (c) 2024 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include <stdio.h>
#include <string.h>

#include <onyx/cpio.h>
#include <onyx/err.h>

struct cpio_header
{
    char sig[6];
    char ino[8];
    char mode[8];
    char uid[8];
    char gid[8];
    char nlinks[8];
    char mtime[8];
    char size[8];
    char maj[8];
    char min[8];
    char smaj[8];
    char smin[8];
    char path_len[8];
    char csum[8];
    char path[];
};

static unsigned int parse_hex(const char *str, unsigned int len)
{
    unsigned int a = 0;
    while (len--)
    {
        char c = *str;
        a *= 16;
        if (c >= '0' && c <= '9')
            a += c - '0';
        else
            a += 10 + c - (c >= 'a' ? 'a' : 'A');
        str++;
    }

    return a;
}

int find_early_cpio_on(const char *filename, void *cpio_archive, size_t cpio_size,
                       struct cpio_file *out)
{
    struct cpio_header *hdr = cpio_archive;
    void *end = cpio_archive + cpio_size;

    while ((void *) hdr < end)
    {
        unsigned int path_len = parse_hex(hdr->path_len, 8);
        unsigned int size = parse_hex(hdr->size, 8);
        if (!strcmp(hdr->path, "TRAILER!!!"))
            break;

        char *data = (char *) ALIGN_TO(hdr->path + path_len, 4);

        if (!strcmp(hdr->path, filename))
        {
            out->data = data;
            out->size = size;
            return 0;
        }

        hdr = (struct cpio_header *) ALIGN_TO(data + size, 4);
    }

    return -ENOENT;
}
