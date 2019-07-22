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

#ifdef CONFIG_KTEST_MTX
static struct mutex mtx = {0};

void sem_test_mtx(void *ctx)
{
	while(true)
	{
		mutex_lock(&mtx);
		//printk("B");
		mutex_unlock(&mtx);
	}
}

void mutex_test(void)
{
	struct thread *t = sched_create_thread(sem_test_mtx, THREAD_KERNEL, NULL);
	assert(t != NULL);
	sched_start_thread(t);

	while(true)
	{
		mutex_lock(&mtx);
		//printk("A");
		mutex_unlock(&mtx);
		printk("ping");
	}

}

bool waiting_for_ack = false;
bool ack = false;

void sleep_wait_for_ack(void)
{
	waiting_for_ack = true;

	uint64_t t = get_tick_count();

	while(t + 10 >= get_tick_count())
	{
		if(ack == true)
		{
			ack = false;
			waiting_for_ack = false;
			return;
		}
	}

	if(ack == false)
	{
		panic("timed out waiting for thread, test failed\n");
	}
}

void sleep_do_ack(void)
{
	waiting_for_ack = false;
	ack = true;
}

void sleep_test_t2(void *ctx)
{
	unsigned int sleep_nr = 0;
	while(true)
	{
		sched_sleep(1);
		sleep_do_ack();
		sleep_nr++;
	}
}

void sleep_test(void)
{
	struct thread *t = sched_create_thread(sleep_test_t2, THREAD_KERNEL, NULL);
	assert(t != NULL);
	sched_start_thread(t);
	volatile unsigned int sleep_nr = 0;

	while(true)
	{
		sched_sleep(1);
		sleep_wait_for_ack();
		sleep_nr++;

		if(sleep_nr == 500)
		{
			sched_remove_thread(t);
			printk("SLEEP TEST: Passed!\n");
			return;
		}
	}
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
