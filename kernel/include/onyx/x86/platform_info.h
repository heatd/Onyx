/*
 * Copyright (c) 2018 - 2021 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef _ONYX_X86_PLATFORM_INFO_H
#define _ONYX_X86_PLATFORM_INFO_H

#include <stdbool.h>
#include <stdint.h>

enum i8042_status
{
    I8042_PLATFORM_ABSENT = 0,
    I8042_FIRMWARE_ABSENT,
    I8042_EXPECTED_PRESENT
};

/* Linux-like x86_platform struct */
struct x86_platform_info
{
    bool has_msi;
    bool has_legacy_devices;
    bool has_rtc;
    bool has_vga;
    enum i8042_status i8042;
};

extern struct x86_platform_info x86_platform;

#endif
