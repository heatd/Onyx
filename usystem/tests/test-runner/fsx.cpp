/*
 * Copyright (c) 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#include <err.h>
#include <unistd.h>

#include <filesystem>

#include "include/process.h"
#include "include/test.h"

struct fsx_test : public test
{
    std::filesystem::path exec_path_;

    fsx_test(std::filesystem::path &&exec, std::string &&name, int timeout_seconds = -1)
        : test{std::move(name), timeout_seconds}, exec_path_{std::move(exec)}
    {
    }

    test_result run_test() const override;
};

#define FSX_TEST_DURATION 60

test_result fsx_test::run_test() const
{
    if (access(exec_path_.c_str(), X_OK) < 0)
        return test_result::skip;

    // Make sure fsx-testfile doesn't exist before we start rerunning
    unlink("fsx-testfile");

    pid_t pid = run_process(exec_path_, {"fsx", "-d", "1m", "fsx-testfile"}, environ);

    if (pid < 0)
    {
        warn("run_process");
        return test_result::exec_error;
    }

    return wait_for_process(pid, "fsx", timeout_seconds_);
}

const fsx_test fsx_t{"/usr/bin/fsx", "fsx", FSX_TEST_DURATION * 3};

const static auto _do = []() {
    register_test(&fsx_t);
    return 0;
}();

// TODO: Do we want some generic "execute-test-and-look-at-result" logic?
// I tried to be very generic for extensibility's sake
