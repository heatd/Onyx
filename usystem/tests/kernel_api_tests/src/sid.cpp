/*
 * Copyright (c) 2021 - 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
#include <fcntl.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cstring>
#include <limits>
#include <string>

#include <gtest/gtest.h>

#include "../include/child_process_helper.h"

TEST(Sid, HandlesProcessGroupLeaders)
{
    auto our_pid = getpid();
    ASSERT_GE(our_pid, 1);

    // We should be running as process group leaders
    ASSERT_EQ(our_pid, getpgrp());

    // setsid() fails if we're already a process group leader as it could
    // break the session <-> pgrp hierarchy.

    ASSERT_EQ(setsid(), -1);
    ASSERT_EQ(errno, EPERM);
}

TEST(Sid, SetsidWorks)
{
    ChildProcessHelper helper;

    auto status = helper([](const ChildProcessHelper& h) { (void) h; },
                         [](const ChildProcessHelper& h) -> int {
                             (void) h;
                             auto our_pid = getpid();
                             if (our_pid < 0)
                                 return 1;

                             // Test basic functionality of setsid and getsid
                             if (setsid() != our_pid)
                                 return 1;
                             if (getsid(0) != our_pid)
                                 return 1;

                             // setsid() makes us process group leaders
                             if (getpgrp() != our_pid)
                                 return 1;

                             return 0;
                         });

    ASSERT_EQ(status, 0);
}
