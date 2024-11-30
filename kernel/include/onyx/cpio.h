/*
 * Copyright (c) 2024 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#ifndef _ONYX_CPIO_H
#define _ONYX_CPIO_H

#include <stddef.h>

#include <onyx/compiler.h>
#include <onyx/types.h>

__BEGIN_CDECLS

struct cpio_file
{
    void *data;
    size_t size;
};

int find_early_cpio_on(const char *filename, void *cpio_archive, size_t cpio_size,
                       struct cpio_file *out);
int find_early_cpio(const char *filename, struct cpio_file *out);

__END_CDECLS

#endif
