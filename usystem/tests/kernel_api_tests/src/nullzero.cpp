/*
 * Copyright (c) 2021 - 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
#include <fcntl.h>
#include <signal.h>
#include <sys/mman.h>
#include <unistd.h>

#include <chrono>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

#include <gtest/gtest.h>

TEST(DevNull, ReadTest)
{
    char buf[10];
    int fd = open("/dev/null", O_RDONLY);
    ASSERT_NE(fd, -1);

    EXPECT_EQ(read(fd, buf, 10), 0);
    close(fd);
}

TEST(DevNull, WriteTest)
{
    char buf[10] = {};
    int fd = open("/dev/null", O_WRONLY);
    ASSERT_NE(fd, -1);

    EXPECT_EQ(write(fd, buf, 10), 10);
    close(fd);
}

TEST(DevZero, ReadTest)
{
    unsigned int num;
    int fd = open("/dev/zero", O_RDONLY);
    ASSERT_NE(fd, -1);

    EXPECT_EQ(read(fd, (void *) &num, sizeof(unsigned int)), (ssize_t) sizeof(unsigned int));
    close(fd);

    EXPECT_EQ(num, 0U);
}

TEST(DevZero, WriteTest)
{
    char buf[10] = {};
    int fd = open("/dev/null", O_WRONLY);
    ASSERT_NE(fd, -1);

    EXPECT_EQ(write(fd, buf, 10), 10);
    close(fd);
}

TEST(DevZero, MmapTest)
{
    int fd = open("/dev/zero", O_RDONLY);

    ASSERT_NE(fd, -1);

    void *ptr = mmap(nullptr, 0x10000, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);

    ASSERT_NE(ptr, MAP_FAILED);

    memset(ptr, 0, 0x10000);

    munmap(ptr, 0x10000);

    close(fd);
}

TEST(DevNull, MmapFailureTest)
{
    int fd = open("/dev/null", O_RDONLY);

    ASSERT_NE(fd, -1);

    void *ptr = mmap(nullptr, 0x10000, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);

    ASSERT_EQ(ptr, MAP_FAILED);

    close(fd);
}
