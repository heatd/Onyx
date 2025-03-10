/*
 * Copyright (c) 2025 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#ifndef _ONYX_COREDUMP_H
#define _ONYX_COREDUMP_H

#include <uapi/signal.h>

struct file;

struct core_vma
{
    unsigned long start;
    unsigned long end;
    unsigned long dump_len;
    unsigned long offset;
    unsigned int flags;
    struct file *file;
};

struct core_state
{
    struct file *core_file;
    struct core_vma *vmas;
    unsigned int nr_vmas;
    int signo;
    siginfo_t *siginfo;
    unsigned long core_limit;
};

void do_coredump(int sig, siginfo_t *siginfo);
int dump_write(struct core_state *state, const void *buf, size_t len);
off_t dump_offset(struct core_state *state);
int dump_align(struct core_state *state, unsigned int alignment);
int dump_vma(struct core_state *state, struct core_vma *vma);

#endif
