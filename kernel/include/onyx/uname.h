/*
 * Copyright (c) 2016 - 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#ifndef _ONYX_UNAME_H
#define _ONYX_UNAME_H

#include <onyx/utils.h>

#define OS_NAME              "Onyx"
#define OS_TAGLINE           "hey it's me, your unix"
#define OS_RELEASE           "onyx-rolling"
#define OS_RELEASE_WITH_TAGS OS_RELEASE KERNEL_TAGS
#define OS_VERSION           "SMP " __DATE__ " " __TIME__

#if defined(__x86_64__)
#define OS_MACHINE "x86_64"
#elif defined(__riscv)
#define OS_MACHINE "riscv64"
#elif defined(__aarch64__)
#define OS_MACHINE "arm64"
#else
#error "Define a machine string for your architecture"
#endif

#endif
