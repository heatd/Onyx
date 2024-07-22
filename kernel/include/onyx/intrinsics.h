/*
 * Copyright (c) 2021 - 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 */

#ifndef _ONYX_INTRINSICS_H
#define _ONYX_INTRINSICS_H

#if __x86_64__
#include <onyx/x86/intrinsics.h>
#elif __riscv
#include <onyx/riscv/intrinsics.h>
#elif __aarch64__
#include <onyx/arm64/intrinsics.h>
#else
#error "Intrinsics not implemented for ARCH"
#endif

#endif
