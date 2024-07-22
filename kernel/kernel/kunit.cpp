/*
 * Copyright (c) 2022 - 2024 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#define pr_fmt(fmt) "kunit: " fmt
#include <onyx/init.h>
#include <onyx/kunit.h>
#include <onyx/vector.h>

extern "C"
{
void ubsan_enter_kunit();
void ubsan_exit_kunit();
}

namespace internal
{

cul::vector<onx::test *> tests;

}

void test_register(onx::test *t)
{
    bool success = internal::tests.push_back(t);

    if (!success)
        panic("Failed to register test %s\n", t->name_);
}

void kunit_do_tests()
{
    unsigned int failed = 0;
    unsigned int done = 0;

#ifdef CONFIG_UBSAN
    ubsan_enter_kunit();
#endif

    for (auto t : internal::tests)
    {
        t->do_test();
        if (!t->__success_)
            failed++;
        done++;
    }

#ifdef CONFIG_UBSAN
    ubsan_exit_kunit();
#endif

    pr_warn("tests done -- %u tests executed, %u failed\n", done, failed);
}

INIT_LEVEL_CORE_KERNEL_ENTRY(kunit_do_tests);
