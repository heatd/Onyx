/*
 * Copyright (c) 2024 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef _ONYX_READAHEAD_H
#define _ONYX_READAHEAD_H

#include <onyx/compiler.h>

__BEGIN_CDECLS

int filemap_do_readahead_async(struct inode *inode, struct readahead_state *ra_state,
                               unsigned long pgoff);

int filemap_do_readahead_sync(struct inode *inode, struct readahead_state *ra_state,
                              unsigned long pgoff);

__END_CDECLS
#endif
