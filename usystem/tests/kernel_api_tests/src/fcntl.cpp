/*
 * Copyright (c) 2022 - 2024 Pedro Falcato
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

static bool flock_is(const struct flock &lock, off_t start, off_t len, short type, pid_t pid)
{
    return lock.l_start == start && lock.l_len == len && lock.l_type == type && lock.l_pid == pid;
}

TEST(posix_adv_locks, test_lock_splitting)
{
    /* Check if lock splitting seems to work properly. We consider a few cases (detailed below). */
    struct flock lock, lock2;
    onx::unique_fd fd = open("flock_file", O_RDWR | O_TRUNC | O_CREAT, 0644);
    onx::unique_fd fd2 = open("flock_file", O_RDWR | O_TRUNC | O_CREAT, 0644);
    ASSERT_TRUE(fd.valid());
    ASSERT_TRUE(fd2.valid());
    ASSERT_EQ(unlink("flock_file"), 0);

    /* 1) Check if the initial lock looks okay */
    lock.l_type = F_WRLCK;
    lock.l_start = 0;
    lock.l_len = 16;
    lock.l_pid = 0;
    lock.l_whence = SEEK_SET;
    lock2 = lock;
    ASSERT_EQ(fcntl(fd.get(), F_OFD_SETLK, &lock), 0);
    ASSERT_EQ(fcntl(fd2.get(), F_OFD_GETLK, &lock2), 0);
    EXPECT_TRUE(flock_is(lock2, lock.l_start, lock.l_len, lock.l_type, -1));

    /* 2) Does trimming the edges look okay? */
    lock2 = lock;
    lock.l_type = F_UNLCK;
    lock.l_len = 1;
    ASSERT_EQ(fcntl(fd.get(), F_OFD_SETLK, &lock), 0);
    ASSERT_EQ(fcntl(fd2.get(), F_OFD_GETLK, &lock2), 0);
    EXPECT_TRUE(flock_is(lock2, 1, 15, F_WRLCK, -1));

    lock.l_start = 15;
    lock.l_len = 32;
    ASSERT_EQ(fcntl(fd.get(), F_OFD_SETLK, &lock), 0);
    lock2.l_pid = 0;
    ASSERT_EQ(fcntl(fd2.get(), F_OFD_GETLK, &lock2), 0);
    EXPECT_TRUE(flock_is(lock2, 1, 14, F_WRLCK, -1));

    /* 3) Poke a hole */
    lock.l_start = 5;
    lock.l_len = 3;
    ASSERT_EQ(fcntl(fd.get(), F_OFD_SETLK, &lock), 0);
    lock2.l_pid = 0;
    ASSERT_EQ(fcntl(fd2.get(), F_OFD_GETLK, &lock2), 0);
    EXPECT_TRUE(flock_is(lock2, 1, 4, F_WRLCK, -1));
    lock2.l_pid = 0;
    lock2.l_start = 8;
    lock2.l_len = 16;
    ASSERT_EQ(fcntl(fd2.get(), F_OFD_GETLK, &lock2), 0);
    EXPECT_TRUE(flock_is(lock2, 8, 7, F_WRLCK, -1));

    /* 4) Unlock it all */
    lock.l_start = 0;
    lock.l_len = 16;
    ASSERT_EQ(fcntl(fd.get(), F_OFD_SETLK, &lock), 0);
    lock2.l_start = 0;
    lock2.l_len = 16;
    lock2.l_pid = 0;
    ASSERT_EQ(fcntl(fd2.get(), F_OFD_GETLK, &lock2), 0);
    EXPECT_TRUE(flock_is(lock2, 0, 16, F_UNLCK, 0));
}

TEST(posix_adv_locks, test_lock_excl)
{
    /* Check if exclusive excludes with other lockers */
    struct flock lock;
    onx::unique_fd fd = open("flock_file", O_RDWR | O_TRUNC | O_CREAT, 0644);
    onx::unique_fd fd2 = open("flock_file", O_RDWR | O_TRUNC | O_CREAT, 0644);
    ASSERT_TRUE(fd.valid());
    ASSERT_TRUE(fd2.valid());
    ASSERT_EQ(unlink("flock_file"), 0);

    lock.l_type = F_RDLCK;
    lock.l_start = 0;
    lock.l_len = 16;
    lock.l_pid = 0;
    lock.l_whence = SEEK_SET;
    ASSERT_EQ(fcntl(fd.get(), F_OFD_SETLK, &lock), 0);

    lock.l_type = F_WRLCK;
    lock.l_start = 0;
    lock.l_len = 16;
    lock.l_pid = 0;
    lock.l_whence = SEEK_SET;
    EXPECT_EQ(fcntl(fd2.get(), F_OFD_SETLK, &lock), -1);
    EXPECT_EQ(errno, EAGAIN);

    lock.l_type = F_WRLCK;
    EXPECT_EQ(fcntl(fd.get(), F_OFD_SETLK, &lock), 0);
    EXPECT_EQ(fcntl(fd2.get(), F_OFD_SETLK, &lock), -1);
    EXPECT_EQ(errno, EAGAIN);

    lock.l_type = F_UNLCK;
    EXPECT_EQ(fcntl(fd.get(), F_OFD_SETLK, &lock), 0);
    EXPECT_EQ(fcntl(fd2.get(), F_OFD_SETLK, &lock), 0);
}

TEST(posix_adv_locks, test_lock_shared)
{
    /* Check if readers properly exclude with writers, but work with readers */
    struct flock lock;
    onx::unique_fd fd = open("flock_file", O_RDWR | O_TRUNC | O_CREAT, 0644);
    onx::unique_fd fd2 = open("flock_file", O_RDWR | O_TRUNC | O_CREAT, 0644);
    ASSERT_TRUE(fd.valid());
    ASSERT_TRUE(fd2.valid());
    ASSERT_EQ(unlink("flock_file"), 0);

    lock.l_type = F_RDLCK;
    lock.l_start = 0;
    lock.l_len = 16;
    lock.l_pid = 0;
    lock.l_whence = SEEK_SET;
    ASSERT_EQ(fcntl(fd.get(), F_OFD_SETLK, &lock), 0);

    lock.l_type = F_RDLCK;
    lock.l_start = 0;
    lock.l_len = 16;
    lock.l_pid = 0;
    lock.l_whence = SEEK_SET;
    EXPECT_EQ(fcntl(fd2.get(), F_OFD_SETLK, &lock), 0);

    lock.l_type = F_WRLCK;
    EXPECT_EQ(fcntl(fd2.get(), F_OFD_SETLK, &lock), -1);
    EXPECT_EQ(errno, EAGAIN);

    lock.l_type = F_UNLCK;
    EXPECT_EQ(fcntl(fd2.get(), F_OFD_SETLK, &lock), 0);

    lock.l_type = F_WRLCK;
    EXPECT_EQ(fcntl(fd.get(), F_OFD_SETLK, &lock), 0);

    lock.l_type = F_RDLCK;
    EXPECT_EQ(fcntl(fd2.get(), F_OFD_SETLK, &lock), -1);
    EXPECT_EQ(errno, EAGAIN);
}

TEST(posix_adv_locks, test_close_unlock)
{
    /* Test if file close properly unlocks the file description's locks */
    struct flock lock;
    onx::unique_fd fd = open("flock_file", O_RDWR | O_TRUNC | O_CREAT, 0644);
    onx::unique_fd fd2 = open("flock_file", O_RDWR | O_TRUNC | O_CREAT, 0644);
    ASSERT_TRUE(fd.valid());
    ASSERT_TRUE(fd2.valid());
    ASSERT_EQ(unlink("flock_file"), 0);

    lock.l_type = F_WRLCK;
    lock.l_start = 0;
    lock.l_len = 16;
    lock.l_pid = 0;
    lock.l_whence = SEEK_SET;
    ASSERT_EQ(fcntl(fd.get(), F_OFD_SETLK, &lock), 0);
    ASSERT_EQ(fcntl(fd2.get(), F_OFD_SETLK, &lock), -1);
    EXPECT_EQ(errno, EAGAIN);
    fd.reset(-1);

    ASSERT_EQ(fcntl(fd2.get(), F_OFD_SETLK, &lock), 0);
}
