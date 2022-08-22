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

TEST(File, UtimensWorks)
{
    onx::unique_fd fd =
        open("test_file", O_CREAT | O_TRUNC | O_RDONLY | O_NOCTTY | O_NOATIME | O_CLOEXEC);

    ASSERT_NE(fd, -1);

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
