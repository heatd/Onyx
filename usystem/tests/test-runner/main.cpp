/*
 * Copyright (c) 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
#include <err.h>
#include <getopt.h>

#include <algorithm>
#include <cassert>
#include <string>

#include "include/process.h"
#include "include/test.h"

int option_silent = 0;

// Note: This could be done in a much more plug-and-play way, but atm there's really no point to it.
// Maybe in the future load available test data from the filesystem??

// Blacklist of tests that may not rerun
// kunit is obvious - it already ran.
// net_tests has issues with binding/unbinding of sockets,
// so only run this once.
const std::string no_rerun_tests[] = {"kunit", "net_tests"};

// Flaky tests - these don't fail the test if failing
// TODO: Make these not flaky
const std::string flaky_tests[] = {"net_tests"};

/**
 * @brief Check if a given test is flaky
 * Flaky tests don't count towards failure, but are logged as failed.
 *
 * @param t Test to check.
 * @return True if flaky, else false.
 */
bool is_flaky_test(const test *t)
{
    return std::find(std::cbegin(flaky_tests), std::cend(flaky_tests), t->name_) !=
           std::cend(flaky_tests);
}

/**
 * @brief Convert test_result into a descriptive string
 *
 * @param res test_result to convert
 * @return String that describes the test_result
 */
const char *result_to_string(test_result res)
{
    switch (res)
    {
        case test_result::ok:
            return "PASSED";
        case test_result::exec_error:
            return "FAILED (exec error)";
        case test_result::skip:
            return "SKIPPED";
        case test_result::error:
            return "FAILED";
        default:
            assert(0);
    }
}

struct run_stats
{
    int total{0};
    int passed{0};
    int skipped{0};
    int fail{0};

    run_stats &operator+=(run_stats &rhs)
    {
        passed += rhs.passed;
        total += +rhs.total;
        skipped += rhs.skipped;
        fail += rhs.fail;
        return *this;
    }
};

/**
 * @brief Check if we must not rerun this test
 * Test objects have a dont_re_run, and we have a no_rerun_tests list above.
 *
 * @param t Test to check
 * @return True if we must not rerun, else false.
 */
static bool dont_rerun(const test *t)
{
    return t->dont_re_run || std::find(std::cbegin(no_rerun_tests), std::cend(no_rerun_tests),
                                       t->name_) != std::cend(no_rerun_tests);
}

/**
 * @brief Do a run for the given tests
 *
 * @param tests Tests to execute
 * @param run Run number (from 0 up to desired runs)
 * @return run_stats
 */
static run_stats do_run(const std::vector<const test *> &tests, unsigned long run)
{
    int total = 0;
    int passed = 0;
    int skipped = 0;
    int fail = 0;

    for (auto &t : tests)
    {
        printf("test-runner: Running %s...\n", t->name_.c_str());
        test_result res;

        if (run > 0 && dont_rerun(t))
            res = test_result::skip;
        else
            res = t->run_test();

        printf("test-runner: %s %s\n", t->name_.c_str(), result_to_string(res));

        total++;

        if (res == test_result::ok)
            passed++;
        else if (res == test_result::skip)
            skipped++;
        else if (res == test_result::error || res == test_result::exec_error)
        {
            if (!is_flaky_test(t))
                fail++;
        }
    }

    return run_stats{total, passed, skipped, fail};
}

// This vector is filled by register_test calls, which are called by constructors around the various
// test files.
std::vector<const test *> tests;

/**
 * @brief Register a test
 *
 * @param t Test to register
 */
void register_test(const test *t)
{
    tests.push_back(t);
}

const static struct option options[] = {{"runs", required_argument, NULL, 'r'},
                                        {"silent", no_argument, &option_silent, 1}};

int main(int argc, char **argv, char **envp)
{
#if 0
    // Omit gtest report color from the output
    putenv((char *) "GTEST_COLOR=no");
#endif
    (void) envp;
    run_stats st;
    unsigned long runs = 1;

    int optindex = 0;
    int opt;

    while ((opt = getopt_long_only(argc, argv, "r:s", options, &optindex)) != -1)
    {
        long res = 0;
        switch (opt)
        {
            case 'r':
                errno = 0;
                res = std::strtoul(optarg, nullptr, 10);

                if (errno == ERANGE)
                {
                    perror("strtol");
                    res = 0;
                }

                if (res == 0 || errno == ERANGE)
                {
                    warnx("Bad --runs argument, assuming 1\n");
                    runs = 1;
                }

                runs = res;

                break;
            case 's':
                option_silent = 1;
                break;
        }
    }

    setup_sigchld();

    if (!option_silent)
        printf("test-runner: running tests...\n");

    for (unsigned long i = 0; i < runs; i++)
    {
        if (runs != 1 && !option_silent)
            printf("test-runner: Doing run %lu\n", i);

        run_stats st2 = do_run(tests, i);
        st += st2;

        if (runs != 1 && !option_silent)
            printf("test-runner: run %lu done\n", i);
    }

    if (!option_silent)
        printf("test-runner: done. ran %d tests, passed %d, failed %d, skipped %d (%.2f%%)\n",
               st.total, st.passed, st.total - (st.passed + st.skipped), st.skipped,
               ((float) (st.passed + st.skipped) / st.total) * 100.0f);

    // signal failure if non-flaky failed != 0
    return st.fail != 0;
}
