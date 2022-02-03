/*
 * Copyright (c) 2017 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 */

#include <libtest.h>

#include <iostream>

#define weak_alias(name, aliasname) _weak_alias(name, aliasname)
#define _weak_alias(name, aliasname) \
    extern __typeof(name) aliasname __attribute__((weak, alias(#name)));

extern uintptr_t __start_testcases;
extern uintptr_t __stop_testcases;

int main(void)
{
    struct libtest_test *p = (struct libtest_test *) &__start_testcases;
    struct libtest_test *end = (struct libtest_test *) &__stop_testcases;
    while (p != end)
    {
        for (unsigned long i = 0; i < p->invoke; i++)
        {
            std::cout << "Executing test " << p->name << " [invocation " << i << "] = ";
            const char *result = p->func() ? "success" : "failure";
            std::cout << result << std::endl;
        }

        p++;
    }
    return 0;
}

// weak_alias(test_do_tests, main);
