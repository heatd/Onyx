/*
 * Copyright (c) 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
#include <err.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#include "include/test.h"

struct kunit_test : public test
{
    kunit_test() : test{"kunit", 0}
    {
        dont_re_run = true;
    }

    test_result run_test() const override;
};

test_result kunit_test::run_test() const
{
    // Get the dmesg
    int size = (int) syscall(SYS_syslog, 10, nullptr, -1);
    if (size < 0)
        err(1, "syslog");

    std::string log;
    log.resize(size);

    if (syscall(SYS_syslog, 2, log.data(), size) < 0)
        err(1, "syslog");

    // Now look for "kunit: tests done --" and get that line
    auto pos = log.find("kunit: tests done --");

    if (pos == std::string::npos)
        return test_result::skip;

    const char *s = log.data() + pos;

    unsigned int total = 0;
    unsigned int failed = 0;

    if (sscanf(s, "kunit: tests done -- %u tests executed, %u", &total, &failed) != 2)
    {
        warnx("kunit_test: Kernel broke kunit result log format...\n");
        return test_result::error;
    }

    printf("kunit: tests done -- %u tests executed, %u failed\n", total, failed);

    return failed != 0 ? test_result::error : test_result::ok;
}

static kunit_test ku;

const static auto _do = []() {
    register_test(&ku);
    return 0;
}();
