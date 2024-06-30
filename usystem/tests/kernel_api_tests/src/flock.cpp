/*
 * Copyright (c) 2024 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#include <errno.h>
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

#include <gtest/gtest.h>
#include <libonyx/unique_fd.h>

TEST(flock, exclusive_works)
{
    onx::unique_fd fd = open("flock_file", O_RDWR | O_TRUNC | O_CREAT, 0644);
    onx::unique_fd fd2 = open("flock_file", O_RDWR, 0644);
    ASSERT_TRUE(fd.valid());
    ASSERT_EQ(unlink("flock_file"), 0);
    ASSERT_TRUE(fd2.valid());

    /* Check if ex-ex conflicts */
    ASSERT_EQ(flock(fd.get(), LOCK_EX | LOCK_NB), 0);
    ASSERT_EQ(flock(fd2.get(), LOCK_EX | LOCK_NB), -1);
    EXPECT_EQ(errno, EWOULDBLOCK);

    /* Check if unlocking and doing ex works */
    ASSERT_EQ(flock(fd.get(), LOCK_UN), 0);
    ASSERT_EQ(flock(fd2.get(), LOCK_EX | LOCK_NB), 0);

    /* Check if closing unlocks */
    fd2.reset(-1);
    ASSERT_EQ(flock(fd.get(), LOCK_EX | LOCK_NB), 0);
}

TEST(flock, shared_works)
{
    onx::unique_fd fd = open("flock_file", O_RDWR | O_TRUNC | O_CREAT, 0644);
    onx::unique_fd fd2 = open("flock_file", O_RDWR, 0644);
    ASSERT_TRUE(fd.valid());
    ASSERT_EQ(unlink("flock_file"), 0);
    ASSERT_TRUE(fd2.valid());

    /* Check if sh-sh works */
    ASSERT_EQ(flock(fd.get(), LOCK_SH | LOCK_NB), 0);
    ASSERT_EQ(flock(fd2.get(), LOCK_SH | LOCK_NB), 0);

    /* Check if ex-sh and sh-ex fails */
    ASSERT_EQ(flock(fd2.get(), LOCK_UN | LOCK_NB), 0);
    ASSERT_EQ(flock(fd2.get(), LOCK_EX | LOCK_NB), -1);
    EXPECT_EQ(errno, EWOULDBLOCK);
    ASSERT_EQ(flock(fd.get(), LOCK_UN | LOCK_NB), 0);
    ASSERT_EQ(flock(fd2.get(), LOCK_EX | LOCK_NB), 0);
    ASSERT_EQ(flock(fd.get(), LOCK_SH | LOCK_NB), -1);
    EXPECT_EQ(errno, EWOULDBLOCK);

    /* Check if unlocking and doing sh works */
    ASSERT_EQ(flock(fd2.get(), LOCK_UN | LOCK_NB), 0);
    ASSERT_EQ(flock(fd.get(), LOCK_SH | LOCK_NB), 0);
}

TEST(flock, upgrade_works)
{
    onx::unique_fd fd = open("flock_file", O_RDWR | O_TRUNC | O_CREAT, 0644);
    onx::unique_fd fd2 = open("flock_file", O_RDWR, 0644);
    ASSERT_TRUE(fd.valid());
    ASSERT_EQ(unlink("flock_file"), 0);
    ASSERT_TRUE(fd2.valid());

    /* Check sh -> ex */
    ASSERT_EQ(flock(fd.get(), LOCK_SH | LOCK_NB), 0);
    ASSERT_EQ(flock(fd.get(), LOCK_EX | LOCK_NB), 0);
    ASSERT_EQ(flock(fd2.get(), LOCK_EX | LOCK_NB), -1);
    EXPECT_EQ(errno, EWOULDBLOCK);

    /* And reverse */
    ASSERT_EQ(flock(fd.get(), LOCK_SH | LOCK_NB), 0);
    ASSERT_EQ(flock(fd2.get(), LOCK_SH | LOCK_NB), 0);
}

TEST(flock, relocking_works)
{
    /* Check if silly relocking works without issues */
    onx::unique_fd fd = open("flock_file", O_RDWR | O_TRUNC | O_CREAT, 0644);
    onx::unique_fd fd2 = open("flock_file", O_RDWR, 0644);
    ASSERT_TRUE(fd.valid());
    ASSERT_EQ(unlink("flock_file"), 0);
    ASSERT_TRUE(fd2.valid());

    ASSERT_EQ(flock(fd.get(), LOCK_SH | LOCK_NB), 0);
    ASSERT_EQ(flock(fd.get(), LOCK_SH | LOCK_NB), 0);
    ASSERT_EQ(flock(fd.get(), LOCK_UN), 0);
    /* Should be unlocked, shared doesn't stack */
    ASSERT_EQ(flock(fd.get(), LOCK_EX | LOCK_NB), 0);
    ASSERT_EQ(flock(fd.get(), LOCK_EX | LOCK_NB), 0);
    ASSERT_EQ(flock(fd.get(), LOCK_UN), 0);
    ASSERT_EQ(flock(fd2.get(), LOCK_EX | LOCK_NB), 0);
}
