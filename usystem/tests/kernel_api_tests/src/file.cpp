/*
 * Copyright (c) 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <gtest/gtest.h>
#include <libonyx/unique_fd.h>

#include "../include/drop_priv.h"

TEST(File, UtimensWorks)
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

    struct stat buf;
    ASSERT_NE(fstat(fd.get(), &buf), -1);

    EXPECT_EQ(buf.st_atim.tv_sec, 0);
}

TEST(File, ChownWorks)
{
    if (getuid() != 0)
    {
        // Let's require root for this one.
        GTEST_SKIP();
    }

    onx::unique_fd fd =
        open("test_file", O_CREAT | O_TRUNC | O_RDONLY | O_NOCTTY | O_NOATIME | O_CLOEXEC, 0777);

    ASSERT_TRUE(fd.valid());

    // Unlink it straight away, as it is a temporary file
    ASSERT_NE(unlink("test_file"), -1);

    ASSERT_NE(fchown(fd.get(), 10, -1), -1);
    struct stat buf;
    ASSERT_NE(fstat(fd.get(), &buf), -1);
    ASSERT_EQ(buf.st_uid, 10u);
}

TEST(File, UnprivilegedChownWorks)
{
    if (getuid() != 0)
    {
        // Let's require root for this one.
        GTEST_SKIP();
    }

    onx::unique_fd fd =
        open("test_file", O_CREAT | O_TRUNC | O_RDONLY | O_NOCTTY | O_NOATIME | O_CLOEXEC, 0777);

    ASSERT_TRUE(fd.valid());

    // Unlink it straight away, as it is a temporary file
    ASSERT_NE(unlink("test_file"), -1);

    ASSERT_NE(fchown(fd.get(), 10, -1), -1);

    unprivileged_guard g;
    ASSERT_NE(fchown(fd.get(), -1, 10), -1);
    struct stat buf;
    ASSERT_NE(fstat(fd.get(), &buf), -1);
    ASSERT_EQ(buf.st_gid, 10u);
}

TEST(File, UnprivilegedChownPermissionChecks)
{
    if (getuid() != 0)
    {
        // Let's require root for this one.
        GTEST_SKIP();
    }

    onx::unique_fd fd =
        open("test_file", O_CREAT | O_TRUNC | O_RDONLY | O_NOCTTY | O_NOATIME | O_CLOEXEC, 0777);

    ASSERT_TRUE(fd.valid());

    // Unlink it straight away, as it is a temporary file
    ASSERT_NE(unlink("test_file"), -1);

    // Only root may change uid owners
    {
        unprivileged_guard g;

        ASSERT_EQ(fchown(fd.get(), 10, -1), -1);
        ASSERT_EQ(errno, EPERM);

        // Unprivileged users may not switch groups if they're not the owners
        ASSERT_EQ(fchown(fd.get(), -1, 10), -1);
        ASSERT_EQ(errno, EPERM);
    }

    ASSERT_NE(fchown(fd.get(), 10, -1), -1);

    // Unprivileged users may change groups if they are in them, and own the file
    {
        unprivileged_guard g;

        // You can't.
        ASSERT_EQ(fchown(fd.get(), -1, 11), -1);
        ASSERT_EQ(errno, EPERM);

        // Unprivileged users may switch groups if they are in the group they are setting
        // Lets test SUID and SGID clearing behavior here as well
        ASSERT_EQ(fchmod(fd.get(), 0777 | S_ISUID | S_ISGID), 0);
        ASSERT_EQ(fchown(fd.get(), -1, 10), 0);
        struct stat buf;
        ASSERT_NE(fstat(fd.get(), &buf), -1);
        ASSERT_TRUE((buf.st_mode & (S_ISUID | S_ISGID)) == 0);
    }
}

TEST(File, ChownDoesntClearMandatoryLocking)
{
    if (getuid() != 0)
    {
        // Let's require root for this one.
        GTEST_SKIP();
    }

    onx::unique_fd fd =
        open("test_file", O_CREAT | O_TRUNC | O_RDONLY | O_NOCTTY | O_NOATIME | O_CLOEXEC, 0777);

    ASSERT_TRUE(fd.valid());

    ASSERT_NE(unlink("test_file"), -1);

    ASSERT_EQ(fchmod(fd.get(), S_ISGID), 0);

    ASSERT_EQ(fchown(fd.get(), 1, -1), 0);

    struct stat buf;
    ASSERT_NE(fstat(fd.get(), &buf), -1);
    ASSERT_TRUE((buf.st_mode & S_ISGID) == S_ISGID);
}
