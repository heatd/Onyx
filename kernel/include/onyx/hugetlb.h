/*
 * Copyright (c) 2024 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#ifndef _ONYX_HUGETLB_H
#define _ONYX_HUGETLB_H

#include <stddef.h>

#include <onyx/compiler.h>

struct file;
struct vm_operations;

__BEGIN_CDECLS

unsigned int hugetlb_pagesize(void);

struct file *hugetlb_new_file(size_t size);

extern const struct vm_operations hugetlb_vmops;

__END_CDECLS

#endif
