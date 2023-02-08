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

struct gtest_test : public test
{
    std::filesystem::path exec_path_;
    gtest_test(std::filesystem::path &&exec, std::string &&name, int timeout_seconds = -1)
        : test{std::move(name), timeout_seconds}, exec_path_{std::move(exec)}
    {
    }
    test_result run_test() const override;
};

const gtest_test gtests[] = {
    gtest_test(std::filesystem::path("/usr/bin/kernel_api_tests"), "kernel_api_tests", 240),
    gtest_test(std::filesystem::path("/usr/bin/net_tests"), "net_tests", 30)};

test_result gtest_test::run_test() const
{
    if (access(exec_path_.c_str(), X_OK) < 0)
        return test_result::skip;

    pid_t pid = run_process(exec_path_, {name_}, environ);

    if (pid < 0)
    {
        warn("run_process");
        return test_result::exec_error;
    }

    return wait_for_process(pid, name_, timeout_seconds_);
}

const static auto _do = []() {
    register_tests(gtests);
    return 0;
}();
