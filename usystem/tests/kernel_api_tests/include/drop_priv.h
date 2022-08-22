/*
 * Copyright (c) 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#pragma once

#include <assert.h>
#include <unistd.h>

#include <gtest/gtest.h>

// Drops from root to a regular user, while being exception/return safe
class unprivileged_guard
{
public:
    unprivileged_guard()
    {
        assert(setegid(10) != -1);
        assert(seteuid(10) != -1);
    }

    ~unprivileged_guard()
    {
        assert(setuid(0) != -1);
        assert(setegid(0) != -1);
    }
};
