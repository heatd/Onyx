/*
 * Copyright (c) 2021 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 */
#include <fcntl.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <unistd.h>

#include <chrono>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

#include <gtest/gtest.h>

/* Let's test resource exaustion */
TEST(Rlimit, Mmap)
{
    rlimit r;
    r.rlim_max = RLIM_INFINITY;
    r.rlim_cur = 0x1000;
    ASSERT_EQ(setrlimit(RLIMIT_AS, &r), 0);

    EXPECT_EQ(mmap(nullptr, 0x10000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0),
              MAP_FAILED);
    EXPECT_EQ(errno, ENOMEM);

    r.rlim_cur = RLIM_INFINITY;

    ASSERT_EQ(setrlimit(RLIMIT_AS, &r), 0);
}

TEST(Rlimit, Fd)
{
    rlimit r;
    r.rlim_max = RLIM_INFINITY;
    r.rlim_cur = 1;
    ASSERT_EQ(setrlimit(RLIMIT_NOFILE, &r), 0);

    EXPECT_EQ(open("/dev/null", O_RDONLY), -1);
    EXPECT_EQ(errno, EMFILE);

    r.rlim_cur = RLIM_INFINITY;

    ASSERT_EQ(setrlimit(RLIMIT_NOFILE, &r), 0);
}
