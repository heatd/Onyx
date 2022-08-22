/*
 * Copyright (c) 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <gtest/gtest.h>
#include <libonyx/unique_fd.h>

#include "../include/drop_priv.h"

TEST(Fcntl, ONoAtimeWorks)
{
    onx::unique_fd fd =
        open("test_file", O_CREAT | O_TRUNC | O_RDONLY | O_NOCTTY | O_NOATIME | O_CLOEXEC, 0777);

    ASSERT_TRUE(fd.valid());

    // Unlink it straight away, as it is a temporary file
    ASSERT_NE(unlink("test_file"), -1);

    struct timespec ts[2];
    ts[0].tv_sec = 0;
    ts[0].tv_nsec = 0;
    ts[1].tv_sec = 0;
    ts[1].tv_nsec = UTIME_OMIT;
    ASSERT_NE(futimens(fd.get(), ts), -1);

    char c;
    auto st = read(fd.get(), &c, 1);
    EXPECT_EQ(st, (ssize_t) 0);

    struct stat buf;
    ASSERT_NE(fstat(fd.get(), &buf), -1);

    EXPECT_EQ(buf.st_atim.tv_sec, 0);
}

TEST(Fcntl, ONoAtimePrivCheck)
{
    onx::unique_fd fd =
        open("test_file", O_CREAT | O_TRUNC | O_RDONLY | O_NOCTTY | O_CLOEXEC, 0777);

    ASSERT_TRUE(fd.valid());

    ASSERT_EQ(fchown(fd, 1, 0), 0);

    // Should work because we're root
    onx::unique_fd fd2 = open("test_file", O_RDONLY | O_CLOEXEC | O_NOATIME);

    ASSERT_TRUE(fd2.valid());
    fd2.release();

    {
        unprivileged_guard g;
        fd2 = open("test_file", O_RDONLY | O_CLOEXEC | O_NOATIME);
        ASSERT_FALSE(fd2.valid());
        ASSERT_EQ(errno, EPERM);

        ASSERT_EQ(fcntl(fd, F_SETFL, O_NOATIME), -1);
        ASSERT_EQ(errno, EPERM);
    }

    ASSERT_NE(unlink("test_file"), -1);
}
