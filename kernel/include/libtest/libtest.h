/*
 * Copyright (c) 2017 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 */

#ifndef _LIBTEST_H
#define _LIBTEST_H

#include <stdbool.h>

#include <onyx/compiler.h>
struct libtest_test
{
    bool (*func)();
    const char *name;
    unsigned long invoke;
};

#define DECLARE_TEST(func, times_to_invoke)                                                     \
    __attribute__((section(".testcases"), used, aligned(1))) const struct libtest_test __PASTE( \
        func, __COUNTER__) = {func, STRINGIFY(func), times_to_invoke};

#endif
