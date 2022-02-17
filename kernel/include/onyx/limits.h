/*
 * Copyright (c) 2021 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef _ONYX_LIMITS_H
#define _ONYX_LIMITS_H

#if !__STDC_HOSTED__
#include <limits.h>
#endif

/**
 * Sigh... Compiler weirdness.
 * clang headers only redirect us towards the libc's limits.h when we're STDC_HOSTED.
 * Therefore, we define all sorts of POSIX stuff here, and use the definition of PIPE_BUF as a guard
 * for redefinitions if we're on GCC.
 */

#ifndef PIPE_BUF

#define PIPE_BUF      4096
#define FILESIZEBITS  64
#define NAME_MAX      255
#define SYMLINK_MAX   255
#define PATH_MAX      4096
#define NZERO         20
#define NGROUPS_MAX   32
#define ARG_MAX       131072
#define IOV_MAX       1024
#define SYMLOOP_MAX   40
#define WORD_BIT      32
#define SSIZE_MAX     LONG_MAX
#define TZNAME_MAX    6
#define TTY_NAME_MAX  32
#define HOST_NAME_MAX 255

// TODO: This is incorrect and is only here for .c files in mm/malloc/

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096UL
#endif

#endif

#endif
