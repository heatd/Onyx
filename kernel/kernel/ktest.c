/*
* Copyright (c) 2018 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#include <stdio.h>
#include <assert.h>

#include <onyx/compiler.h>
#include <onyx/page.h>
#include <onyx/panic.h>
#include <onyx/scheduler.h>
#include <onyx/thread.h>
#include <onyx/semaphore.h>
#include <onyx/mutex.h>

#ifdef CONFIG_DO_TESTS

#ifdef CONFIG_KTEST_PAGE_ALLOC

/* Tests the page allocator by dumping every page */
void test_page_alloc(void)
{
	void *ptr = alloc_page(0);

	for(; ptr; ptr = alloc_page(0))
	{
		printf("Page: %p\n", ptr);
	}
	halt();
}
#endif

#ifdef CONFIG_KTEST_SEM
static struct mutex mtx = {0};

void sem_test_signal(void *ctx)
{
	while(true)
	{
		mutex_lock(&mtx);
		sched_sleep(1);
		mutex_unlock(&mtx);
	}
}

void sem_test(void)
{
	struct thread *t = sched_create_thread(sem_test_signal, THREAD_KERNEL, NULL);
	assert(t != NULL);
	sched_start_thread(t);

	while(true)
	{
		mutex_lock(&mtx);
		sched_sleep(1);
		mutex_unlock(&mtx);
	}

}

#endif
void (*tests[])(void) = {
#ifdef CONFIG_KTEST_PAGE_ALLOC
	test_page_alloc,
#endif
#ifdef CONFIG_KTEST_SEM
	sem_test,
#endif
#ifdef CONFIG_KTEST_MUTEX
	mutex_test,
#endif
};


void do_ktests(void)
{
	size_t nr_tests = sizeof(tests) / sizeof(uintptr_t);

	for(size_t i = 0; i < nr_tests; i++)
	{
		tests[i]();
	}
}

#endif
