/*
 * Copyright (c) 2020 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 */
#include <array>
#include <iostream>
#include <mutex>
#include <thread>

#include <test/libtest.h>

static volatile unsigned long counter = 0;
static constexpr size_t nr_threads = 4;
static std::array<std::thread, nr_threads> thread_list;
static std::array<bool, nr_threads> increments;
static std::mutex lock;

static void mutex_func_entry(bool incs)
{
    for (long i = 0; i < (UINT16_MAX); i++)
    {
        lock.lock();

        if (incs)
            counter++;
        else
            counter--;
        lock.unlock();
    }
}

bool mutex_test()
{
    counter = 0;

    for (size_t i = 0; i < nr_threads; i++)
    {
        increments[i] = i % 2;
        thread_list[i] = std::thread{mutex_func_entry, increments[i]};
    }

    for (auto &t : thread_list)
        t.join();

    return counter == 0;
}

DECLARE_TEST(mutex_test, 10);
