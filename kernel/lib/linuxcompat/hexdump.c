/*
 * Copyright (c) 2025 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include <linux/ctype.h>
#include <linux/log2.h>
#include <linux/minmax.h>
#include <linux/printk.h>
#include <linux/types.h>
#include <linux/unaligned.h>

int hex_dump_to_buffer(const void *buf, size_t len, int rowsize, int groupsize, char *linebuf,
                       size_t linebuflen, bool ascii)
{
    size_t nr_groups, i;
    u8 *ptr = (void *) buf, *p;
    int ret = 0, err;

    if (rowsize != 16 && rowsize != 32)
        rowsize = 16;

    if (len > (size_t) rowsize) /* limit to one line at a time */
        len = rowsize;
    if (!is_power_of_2(groupsize) || groupsize > 8)
        groupsize = 1;
    if ((len % groupsize) != 0) /* no mixed size output */
        groupsize = 1;

    nr_groups = len / groupsize;
    for (i = 0; i < nr_groups; i++)
    {
        p = ptr + (i * groupsize);
        switch (groupsize)
        {
            case 1:
                err = snprintf(linebuf + ret, linebuflen - ret, "%s%02x", i ? " " : "",
                               get_unaligned(p));
                break;
            case 2:
                err = snprintf(linebuf + ret, linebuflen - ret, "%s%04x", i ? " " : "",
                               get_unaligned((u16 *) p));
                break;
            case 4:
                err = snprintf(linebuf + ret, linebuflen - ret, "%s%08x", i ? " " : "",
                               get_unaligned((u32 *) p));
                break;
            case 8:
                err = snprintf(linebuf + ret, linebuflen - ret, "%s%016lx", i ? " " : "",
                               get_unaligned((u64 *) p));
                break;
            default:
                UNREACHABLE();
        }

        if (err >= (int) linebuflen - ret)
        {
            /* Overflow of the supplied buffer */
            goto overflow;
        }

        ret += err;
    }

    if (ascii)
    {
        if (linebuflen - ret <= len + 1)
            goto overflow;
        linebuf[ret++] = ' ';
        for (i = 0; i < len; i++)
            linebuf[ret++] = (isascii(ptr[i]) && isprint(ptr[i])) ? ptr[i] : '.';
    }

    linebuf[ret++] = '\0';
    return ret;
overflow:
    /* we require at least len * 2 (2 chars for each byte) + nr_groups (spaces) + len (if ascii) */
    return len * 2 + nr_groups + (ascii ? len : 0);
}

void print_hex_dump(const char *level, const char *prefix_str, int prefix_type, int rowsize,
                    int groupsize, const void *buf, size_t len, bool ascii)
{
    const u8 *ptr = buf;
    size_t i, linelen, remaining = len;
    char linebuf[32 * 3 + 2 + 32 + 1];

    if (rowsize != 16 && rowsize != 32)
        rowsize = 16;

    for (i = 0; i < len; i += rowsize)
    {
        linelen = min(remaining, (size_t) rowsize);
        remaining -= rowsize;

        hex_dump_to_buffer(ptr + i, linelen, rowsize, groupsize, linebuf, sizeof(linebuf), ascii);

        switch (prefix_type)
        {
            case DUMP_PREFIX_ADDRESS:
                printk("%s%s%p: %s\n", level, prefix_str, ptr + i, linebuf);
                break;
            case DUMP_PREFIX_OFFSET:
                printk("%s%s%.8zx: %s\n", level, prefix_str, i, linebuf);
                break;
            default:
                printk("%s%s%s\n", level, prefix_str, linebuf);
                break;
        }
    }
}
