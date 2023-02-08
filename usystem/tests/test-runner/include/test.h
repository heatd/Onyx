/*
 * Copyright (c) 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#pragma once
#include <string>

enum class test_result
{
    ok = 0,
    error = 1,
    skip = 2,
    exec_error
};

/**
 * @brief Represents a generic test skeleton
 * Various test backends then implement this.
 *
 */
struct test
{
    std::string name_;
    int timeout_seconds_ = -1;

    bool dont_re_run = false;

    test(std::string &&name, int timeout_seconds)
        : name_{std::move(name)}, timeout_seconds_{timeout_seconds}
    {
    }

    void no_rerun()
    {
        dont_re_run = true;
    }

    virtual test_result run_test() const = 0;
};

/**
 * @brief Register a test
 *
 * @param t Test to register
 */
void register_test(const test *t);

/**
 * @brief Register tests
 *
 * @tparam Container Container type
 * @param c Container to look at and register tests from
 */
template <typename Container>
void register_tests(const Container &c)
{
    for (auto &t : c)
    {
        register_test(&t);
    }
}
