/*
 * Copyright (c) 2022 Pedro Falcato
 * Copyright 2016 The Fuchsia Authors
 * Copyright (c) 2013, Google, Inc. All rights reserved

 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Note: The checks themselves (UTCHECK*, EXPECT* and ASSERT*) were taken from
 * Fuchsia, also MIT licensed. This is the only thing written by Google/Fuchsia Authors
 * and should possibly be removed for something fancier.
 */
#ifndef _ONYX_KUNIT_H
#define _ONYX_KUNIT_H

#include <inttypes.h>

namespace onx
{

struct test
{
    const char* name_;
    bool __success_{true};

    constexpr test(const char* name) : name_{name}
    {
    }
    virtual void do_test() = 0;
};

}; // namespace onx

void test_register(onx::test* t);

#define KUNIT_TEST_NAME(testsuite, name) __onyx_test_##testsuite##_##name

#define FRIEND_TEST(testsuite, name) friend struct KUNIT_TEST_NAME(testsuite, name)

#define TEST(test_suite_name, name)                                         \
    static struct KUNIT_TEST_NAME(test_suite_name, name) : public onx::test \
    {                                                                       \
                                                                            \
        KUNIT_TEST_NAME(test_suite_name, name)                              \
        () : onx::test{#test_suite_name "." #name}                          \
        {                                                                   \
            test_register(this);                                            \
        }                                                                   \
                                                                            \
        void do_test() override;                                            \
    } KUNIT_TEST_NAME(test_suite_name, name##_decl);                        \
                                                                            \
    void KUNIT_TEST_NAME(test_suite_name, name)::do_test()

// A good portion of the checks below were taken from Fuchsia,
//
// This function will help terminate the static analyzer when it reaches
// an assertion failure site. The bugs discovered by the static analyzer will
// be suppressed as they are expected by the test cases.
static inline void unittest_fails()
{
}
/*
 * Macros to format the error string
 */
#define EXPECTED_STRING             "%s:\n        expected "
#define UNITTEST_FAIL_TRACEF_FORMAT "\n        [FAILED]\n        %s:%d:\n        "
#define UNITTEST_FAIL_TRACEF(str, x...)                                              \
    do                                                                               \
    {                                                                                \
        printk(UNITTEST_FAIL_TRACEF_FORMAT str, __PRETTY_FUNCTION__, __LINE__, ##x); \
    } while (0)

#define AUTO_TYPE_VAR(type) auto&
// The following helper function makes the "msg" argument optional so that you can write either:
//   ASSERT_EQ(x, y, "Check that x equals y");
// or
//   ASSERT_EQ(x, y);
static inline constexpr const char* unittest_get_msg(const char* msg = "")
{
    return msg;
}
/*
 * UTCHECK_* macros are used to check test results.  Generally, one should
 * prefer to use either the EXPECT_* (non-terminating) or ASSERT_*
 * (terminating) forms of the macros.  See below.
 *
 * The parameter after |term| is an optional message (const char*) to be printed
 * if the check fails.
 */
#define UTCHECK_EQ(expected, actual, term, ...)                                                    \
    do                                                                                             \
    {                                                                                              \
        const AUTO_TYPE_VAR(expected) _e = (expected);                                             \
        const AUTO_TYPE_VAR(actual) _a = (actual);                                                 \
        if (_e != _a)                                                                              \
        {                                                                                          \
            UNITTEST_FAIL_TRACEF(EXPECTED_STRING "%s (%" PRIdPTR "), "                             \
                                                 "actual %s (%" PRIdPTR ")\n",                     \
                                 unittest_get_msg(__VA_ARGS__), #expected, (intptr_t) _e, #actual, \
                                 (intptr_t) _a);                                                   \
            unittest_fails();                                                                      \
            __success_ = false;                                                                    \
            if (term)                                                                              \
            {                                                                                      \
                return;                                                                            \
            }                                                                                      \
        }                                                                                          \
    } while (0)

#define UTCHECK_NE(expected, actual, term, ...)                                                   \
    do                                                                                            \
    {                                                                                             \
        const AUTO_TYPE_VAR(expected) _e = (expected);                                            \
        const AUTO_TYPE_VAR(actual) _a = (actual);                                                \
        if (_e == (_a))                                                                           \
        {                                                                                         \
            UNITTEST_FAIL_TRACEF(                                                                 \
                EXPECTED_STRING "%s (%" PRIdPTR "), %s"                                           \
                                " to differ, but they are the same %" PRIdPTR "\n",               \
                unittest_get_msg(__VA_ARGS__), #expected, (intptr_t) _e, #actual, (intptr_t) _a); \
            unittest_fails();                                                                     \
            __success_ = false;                                                                   \
            if (term)                                                                             \
            {                                                                                     \
                return;                                                                           \
            }                                                                                     \
        }                                                                                         \
    } while (0)

#define UTCHECK_LE(expected, actual, term, ...)                                                   \
    do                                                                                            \
    {                                                                                             \
        const AUTO_TYPE_VAR(expected) _e = (expected);                                            \
        const AUTO_TYPE_VAR(actual) _a = (actual);                                                \
        if (_e > _a)                                                                              \
        {                                                                                         \
            UNITTEST_FAIL_TRACEF(                                                                 \
                EXPECTED_STRING "%s (%" PRIdPTR ") to be"                                         \
                                " less-than-or-equal-to actual %s (%" PRIdPTR ")\n",              \
                unittest_get_msg(__VA_ARGS__), #expected, (intptr_t) _e, #actual, (intptr_t) _a); \
            unittest_fails();                                                                     \
            __success_ = false;                                                                   \
            if (term)                                                                             \
            {                                                                                     \
                return;                                                                           \
            }                                                                                     \
        }                                                                                         \
    } while (0)

#define UTCHECK_LT(expected, actual, term, ...)                                                    \
    do                                                                                             \
    {                                                                                              \
        const AUTO_TYPE_VAR(expected) _e = (expected);                                             \
        const AUTO_TYPE_VAR(actual) _a = (actual);                                                 \
        if (_e >= _a)                                                                              \
        {                                                                                          \
            UNITTEST_FAIL_TRACEF(EXPECTED_STRING "%s (%" PRIdPTR ") to be"                         \
                                                 " less-than actual %s (%" PRIdPTR ")\n",          \
                                 unittest_get_msg(__VA_ARGS__), #expected, (intptr_t) _e, #actual, \
                                 (intptr_t) _a);                                                   \
            unittest_fails();                                                                      \
            __success_ = false;                                                                    \
            if (term)                                                                              \
            {                                                                                      \
                return;                                                                            \
            }                                                                                      \
        }                                                                                          \
    } while (0)

#define UTCHECK_GE(expected, actual, term, ...)                                                   \
    do                                                                                            \
    {                                                                                             \
        const AUTO_TYPE_VAR(expected) _e = (expected);                                            \
        const AUTO_TYPE_VAR(actual) _a = (actual);                                                \
        if (_e < _a)                                                                              \
        {                                                                                         \
            UNITTEST_FAIL_TRACEF(                                                                 \
                EXPECTED_STRING "%s (%" PRIdPTR ") to be"                                         \
                                " greater-than-or-equal-to actual %s (%" PRIdPTR ")\n",           \
                unittest_get_msg(__VA_ARGS__), #expected, (intptr_t) _e, #actual, (intptr_t) _a); \
            unittest_fails();                                                                     \
            __success_ = false;                                                                   \
            if (term)                                                                             \
            {                                                                                     \
                return;                                                                           \
            }                                                                                     \
        }                                                                                         \
    } while (0)

#define UTCHECK_GT(expected, actual, term, ...)                                                    \
    do                                                                                             \
    {                                                                                              \
        const AUTO_TYPE_VAR(expected) _e = (expected);                                             \
        const AUTO_TYPE_VAR(actual) _a = (actual);                                                 \
        if (_e <= _a)                                                                              \
        {                                                                                          \
            UNITTEST_FAIL_TRACEF(EXPECTED_STRING "%s (%" PRIdPTR ") to be"                         \
                                                 " greater-than actual %s (%" PRIdPTR ")\n",       \
                                 unittest_get_msg(__VA_ARGS__), #expected, (intptr_t) _e, #actual, \
                                 (intptr_t) _a);                                                   \
            unittest_fails();                                                                      \
            __success_ = false;                                                                    \
            if (term)                                                                              \
            {                                                                                      \
                return;                                                                            \
            }                                                                                      \
        }                                                                                          \
    } while (0)

#define UTCHECK_TRUE(actual, term, ...)                                                    \
    if (!(actual))                                                                         \
    {                                                                                      \
        UNITTEST_FAIL_TRACEF("%s: %s is false\n", unittest_get_msg(__VA_ARGS__), #actual); \
        unittest_fails();                                                                  \
                                                                                           \
        __success_ = false;                                                                \
        if (term)                                                                          \
        {                                                                                  \
            return;                                                                        \
        }                                                                                  \
    }

#define UTCHECK_FALSE(actual, term, ...)                                                  \
    if (actual)                                                                           \
    {                                                                                     \
        UNITTEST_FAIL_TRACEF("%s: %s is true\n", unittest_get_msg(__VA_ARGS__), #actual); \
        unittest_fails();                                                                 \
        __success_ = false;                                                               \
        if (term)                                                                         \
        {                                                                                 \
            return;                                                                       \
        }                                                                                 \
    }
#define UTCHECK_NULL(actual, term, ...)                                                        \
    if (actual != NULL)                                                                        \
    {                                                                                          \
        UNITTEST_FAIL_TRACEF("%s: %s is non-null!\n", unittest_get_msg(__VA_ARGS__), #actual); \
        unittest_fails();                                                                      \
        __success_ = false;                                                                    \
        if (term)                                                                              \
        {                                                                                      \
            return;                                                                            \
        }                                                                                      \
    }

#define UTCHECK_NONNULL(actual, term, ...)                                                 \
    if (actual == NULL)                                                                    \
    {                                                                                      \
        UNITTEST_FAIL_TRACEF("%s: %s is null!\n", unittest_get_msg(__VA_ARGS__), #actual); \
        unittest_fails();                                                                  \
        __success_ = false;                                                                \
        if (term)                                                                          \
        {                                                                                  \
            return;                                                                        \
        }                                                                                  \
    }

#define UTCHECK_BYTES_EQ(expected, actual, length, term, ...)                                \
    if (!unittest_expect_bytes((expected), #expected, (actual), #actual, (length),           \
                               unittest_get_msg(__VA_ARGS__), __PRETTY_FUNCTION__, __LINE__, \
                               true))                                                        \
    {                                                                                        \
        unittest_fails();                                                                    \
        __success_ = false;                                                                  \
        if (term)                                                                            \
        {                                                                                    \
            return;                                                                          \
        }                                                                                    \
    }

#define UTCHECK_BYTES_NE(expected, actual, length, term, ...)                                \
    if (!unittest_expect_bytes((expected), #expected, (actual), #actual, (length),           \
                               unittest_get_msg(__VA_ARGS__), __PRETTY_FUNCTION__, __LINE__, \
                               false))                                                       \
    {                                                                                        \
        unittest_fails();                                                                    \
        __success_ = false;                                                                  \
        if (term)                                                                            \
        {                                                                                    \
            return;                                                                          \
        }                                                                                    \
    }
/* EXPECT_* macros check the supplied condition and will print a diagnostic
 * message and flag the test as having failed if the condition fails.  The test
 * will continue to run, even if the condition fails.
 *
 * The last parameter is an optional const char* message to be included in the
 * print diagnostic message.
 */
#define EXPECT_EQ(expected, actual, ...) UTCHECK_EQ(expected, actual, false, __VA_ARGS__)
#define EXPECT_NE(expected, actual, ...) UTCHECK_NE(expected, actual, false, __VA_ARGS__)
#define EXPECT_LE(expected, actual, ...) UTCHECK_LE(expected, actual, false, __VA_ARGS__)
#define EXPECT_LT(expected, actual, ...) UTCHECK_LT(expected, actual, false, __VA_ARGS__)
#define EXPECT_GE(expected, actual, ...) UTCHECK_GE(expected, actual, false, __VA_ARGS__)
#define EXPECT_GT(expected, actual, ...) UTCHECK_GT(expected, actual, false, __VA_ARGS__)
#define EXPECT_TRUE(actual, ...)         UTCHECK_TRUE(actual, false, __VA_ARGS__)
#define EXPECT_FALSE(actual, ...)        UTCHECK_FALSE(actual, false, __VA_ARGS__)
#define EXPECT_BYTES_EQ(expected, actual, length, ...) \
    UTCHECK_BYTES_EQ(expected, actual, length, false, __VA_ARGS__)
#define EXPECT_BYTES_NE(bytes1, bytes2, length, ...) \
    UTCHECK_BYTES_NE(bytes1, bytes2, length, false, __VA_ARGS__)
#define EXPECT_EQ_LL(expected, actual, ...) UTCHECK_EQ_LL(expected, actual, false, __VA_ARGS__)
#define EXPECT_NULL(actual, ...)            UTCHECK_NULL(actual, false, __VA_ARGS__)
#define EXPECT_NONNULL(actual, ...)         UTCHECK_NONNULL(actual, false, __VA_ARGS__)

/* ASSERT_* macros check the condition and will print a message and immediately
 * abort a test with a filure status if the condition fails.
 */
#define ASSERT_EQ(expected, actual, ...) UTCHECK_EQ(expected, actual, true, __VA_ARGS__)
#define ASSERT_NE(expected, actual, ...) UTCHECK_NE(expected, actual, true, __VA_ARGS__)
#define ASSERT_LE(expected, actual, ...) UTCHECK_LE(expected, actual, true, __VA_ARGS__)
#define ASSERT_LT(expected, actual, ...) UTCHECK_LT(expected, actual, true, __VA_ARGS__)
#define ASSERT_GE(expected, actual, ...) UTCHECK_GE(expected, actual, true, __VA_ARGS__)
#define ASSERT_GT(expected, actual, ...) UTCHECK_GT(expected, actual, true, __VA_ARGS__)
#define ASSERT_TRUE(actual, ...)         UTCHECK_TRUE(actual, true, __VA_ARGS__)
#define ASSERT_FALSE(actual, ...)        UTCHECK_FALSE(actual, true, __VA_ARGS__)
#define ASSERT_BYTES_EQ(expected, actual, length, ...) \
    UTCHECK_BYTES_EQ(expected, actual, length, true, __VA_ARGS__)
#define ASSERT_BYTES_NE(bytes1, bytes2, length, ...) \
    UTCHECK_BYTES_NE(bytes1, bytes2, length, true, __VA_ARGS__)
#define ASSERT_EQ_LL(expected, actual, ...) UTCHECK_EQ_LL(expected, actual, true, __VA_ARGS__)
#define ASSERT_NULL(actual, ...)            UTCHECK_NULL(actual, true, __VA_ARGS__)
#define ASSERT_NONNULL(actual, ...)         UTCHECK_NONNULL(actual, true, __VA_ARGS__)

#endif
