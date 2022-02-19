/*
 * Copyright (c) 2018 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 */

#include <assert.h>
#include <stdio.h>

#include <onyx/compiler.h>
#include <onyx/cpu.h>
#include <onyx/mutex.h>
#include <onyx/page.h>
#include <onyx/panic.h>
#include <onyx/scheduler.h>
#include <onyx/semaphore.h>
#include <onyx/thread.h>

#include <libtest/libtest.h>

#include <onyx/linker_section.hpp>

#ifdef CONFIG_DO_TESTS

#ifdef CONFIG_KTEST_PAGE_ALLOC

void __test_page_alloc(void *arg)
{
    (void) arg;
    void *ptr = alloc_page(0);

    for (; ptr; ptr = alloc_page(0))
        ;
}
/* Tests the page allocator by dumping every page */
void test_page_alloc(void)
{
    struct thread *threads[get_nr_cpus()];
    for (int i = 0; i < get_nr_cpus(); ++i)
    {
        threads[i] = sched_create_thread(__test_page_alloc, THREAD_KERNEL, NULL);
        assert(threads[i] != NULL);
    }

    for (int i = 0; i < get_nr_cpus(); ++i)
    {
        sched_start_thread(threads[i]);
    }

    sched_sleep_ms(10000000);
}
#endif

#ifdef CONFIG_KTEST_SPINLOCK

static struct spinlock spl;
static volatile unsigned long counter = 0;

void spinlock_thread_entry(void *arg)
{
    bool incs = get_cpu_nr() % 2;
    for (long i = 0; i < (INT64_MAX); i++)
    {
        spin_lock(&spl);

        if (incs)
            counter++;
        else
            counter--;
        spin_unlock(&spl);
    }
}

void spinlock_test()
{
    unsigned int nr_cpus = get_nr_cpus();
    for (unsigned int i = 0; i < nr_cpus; i++)
    {
        assert(sched_create_thread(spinlock_thread_entry, THREAD_KERNEL, NULL) != NULL);
    }

    printk("Test done.\n");
    assert(counter == 0);
}

#endif

#ifdef CONFIG_KTEST_ALLOC_PAGE_PERF

#include <onyx/clock.h>

void *external_ptr = NULL;

void page_alloc_perf(void)
{
    struct clocksource *c = get_main_clock();

    hrtime_t lowest = UINT64_MAX;
    hrtime_t highest = 0;

    for (int i = 0; i < 40; i++)
    {
        hrtime_t t0 = c->get_ns();

        external_ptr = alloc_pages(1, PAGE_ALLOC_4GB_LIMIT | PAGE_ALLOC_NO_ZERO);
        // external_ptr = vmalloc(16, VM_TYPE_REGULAR, VM_WRITE | VM_READ);
        // vm_munmap(&kernel_address_space, external_ptr, 16);

        hrtime_t t1 = c->get_ns();

        lowest = lowest < (t1 - t0) ? lowest : t1 - t0;
        highest = highest > (t1 - t0) ? highest : t1 - t0;
    }

    printk("Performance: lowest %lu ns - highest %lu ns avg %lu ns\n", lowest, highest,
           (highest + lowest) / 2);
}

#endif

void execute_vm_tests();

static void (*tests[])(void) = {
#ifdef CONFIG_KTEST_PAGE_ALLOC
    test_page_alloc,
#endif
#ifdef CONFIG_KTEST_SLEEP
    sleep_test,
#endif
#ifdef CONFIG_KTEST_MTX
    mutex_test,
#endif
#ifdef CONFIG_VM_TESTS
    execute_vm_tests,
#endif
#ifdef CONFIG_KTEST_SPINLOCK
    spinlock_test,
#endif
#ifdef CONFIG_KTEST_ALLOC_PAGE_PERF
    page_alloc_perf,
#endif
};

void do_ktests_old(void)
{
    size_t nr_tests = sizeof(tests) / sizeof(uintptr_t);

    for (size_t i = 0; i < nr_tests; i++)
    {
        tests[i]();
    }
}

DEFINE_LINKER_SECTION_SYMS(__start_testcases, __end_testcases);

linker_section testcase_section{&__start_testcases, &__end_testcases};

int do_ktests_new(void)
{
    libtest_test *p = testcase_section.as<libtest_test>();
    auto elems = testcase_section.size() / sizeof(libtest_test);

    for (size_t i = 0; i < elems; i++, p++)
    {
        for (unsigned long j = 0; j < p->invoke; j++)
        {
            printk("Executing test %s [invocation %lu] = ", p->name, j);
            const char *result = p->func() ? "success" : "failure";
            printk("%s\n", result);
        }
    }

    return 0;
}

void do_ktests()
{
    do_ktests_old();
    do_ktests_new();
}

#endif
