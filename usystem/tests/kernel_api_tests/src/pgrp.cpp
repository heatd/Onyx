/*
 * Copyright (c) 2020 - 2022 Pedro Falcato
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

TEST(SetPgrpTest, WorksForSelf)
{
    auto pid = getpid();

    ASSERT_NE(pid, -1);

    ASSERT_EQ(setpgid(0, 0), 0);

    ASSERT_EQ(getpgid(0), pid);
}

TEST(SetPgrpTest, WorksForChild)
{
    ChildProcessHelper h;

    auto status = h(
        [](const ChildProcessHelper& context) {
            setpgid(context.pid, context.pid);
            EXPECT_EQ(getpgid(context.pid), context.pid);
        },
        [](const ChildProcessHelper&) -> int { return getpgid(0) == getpid(); });

    EXPECT_EQ(status, true);
}

TEST(SetPgrpTest, HandlesBadPids)
{
    EXPECT_EQ(setpgid(1, 0), -1);
    EXPECT_EQ(errno, ESRCH);

    /* Ugh, PRAY THAT WE HAVEN'T WRAPPED PIDS WHEN WE RUN THIS */
    /* Why is there no permanently invalid pid that isn't 0? :(((( */
    EXPECT_EQ(setpgid(std::numeric_limits<pid_t>::max(), 0), -1);
    EXPECT_EQ(errno, ESRCH);
}

TEST(SetPgrpTest, HandlesChildExec)
{
    ChildProcessHelper h;
    Waiter child_out;

    auto status = h([&](const ChildProcessHelper&) {},
                    [&](const ChildProcessHelper& context) -> int {
                        const auto& w = context.w;
                        w.RemapToStdin();
                        child_out.RemapToStdout();

                        w.Close();
                        child_out.Close();

                        if (execlp("cat", "cat", NULL) < 0)
                        {
                            return -127;
                        }

                        return 0;
                    },
                    [&](const ChildProcessHelper& context) {
                        const auto& w = context.w;
                        child_out.CloseWriteEnd();

                        /* cat will echo our stuff when it sees the newline - it's a way for us to
                         * know for sure it has been exec'd.
                         */

                        w.Write("Test\n", strlen("Test\n"));

                        child_out.Wait();

                        EXPECT_EQ(setpgid(context.pid, context.pid), -1);
                        EXPECT_EQ(errno, EACCES);

                        w.Close();
                    });
    EXPECT_EQ(status, 0);
}

TEST(SetPgrpTest, HandlesNegativeInput)
{
    EXPECT_EQ(setpgid(0, -1), -1);
    EXPECT_EQ(errno, EINVAL);
}

TEST(SetPgrpTest, HandlesEPerm)
{
    // Create multiple children
    Waiter w;
    Waiter parent_wake;

    pid_t pid = fork();

    ASSERT_NE(pid, -1);

    if (pid == 0)
    {
        parent_wake.CloseReadEnd();
        w.CloseWriteEnd();
        w.Wait();

        // Create a new session
        EXPECT_EQ(setsid(), getpid());

        parent_wake.Wake();
        w.Wait();

        exit(0);
    }

    w.CloseReadEnd();
    w.Wake();

    parent_wake.Wait();

    // We're in a different session
    // Testing all EPERMs
    // TODO: Add separate tests for the separate EPERM conditions?
    EXPECT_EQ(setpgid(pid, getpid()), -1);
    EXPECT_EQ(errno, EPERM);

    w.Wake();

    wait(nullptr);
}
