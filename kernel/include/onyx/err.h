/*
 * Copyright (c) 2024 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#ifndef _ONYX_ERR_H
#define _ONYX_ERR_H

#include <onyx/compiler.h>

#include <uapi/errno.h>

#define IS_ERR_VALUE(x) unlikely((unsigned long) (void *) (x) >= (unsigned long) -MAX_ERRNO)
#define ERR_PTR(err)    ((void *) (unsigned long) (err))

#define IS_ERR(x)  IS_ERR_VALUE(x)
#define PTR_ERR(x) ((long) (x))

#define IS_ERR_OR_NULL(x) (unlikely(IS_ERR_VALUE((x)) || (x) == NULL))

#endif
