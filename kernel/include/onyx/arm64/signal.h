/*
 * Copyright (c) 2019 - 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef _ONYX_ARM64_SIGNAL_H
#define _ONYX_ARM64_SIGNAL_H

#include <uapi/signal.h>

struct __sigcontext
{
    unsigned long uc_flags;
    void *uc_unused_link;
    stack_t uc_stack;
    sigset_t uc_sigmask;
    /* We must pad uc_sigmask up to the userspace sigset_t size - 128 bytes */
    unsigned char __padding[128 - sizeof(sigset_t)];
    mcontext_t uc_mcontext;
};

struct sigframe
{
    struct __sigcontext uc;
    siginfo_t sinfo;
};

#endif
