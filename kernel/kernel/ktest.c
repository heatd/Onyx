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
#include <onyx/cpu.h>

#ifdef CONFIG_DO_TESTS

#ifdef CONFIG_KTEST_PAGE_ALLOC

void __test_page_alloc(void *arg)
{
	(void) arg;
	void *ptr = alloc_page(0);

	for(; ptr; ptr = alloc_page(0));
}
/* Tests the page allocator by dumping every page */
void test_page_alloc(void)
{
	struct thread *threads[get_nr_cpus()];
	for(int i = 0; i < get_nr_cpus(); ++i)
	{
		threads[i] = sched_create_thread(__test_page_alloc, THREAD_KERNEL, NULL);
		assert(threads[i] != NULL);
	}

	for(int i = 0; i < get_nr_cpus(); ++i)
	{
		sched_start_thread(threads[i]);
	}

	sched_sleep(10000000);
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

#ifdef CONFIG_KTEST_SPINLOCK

static struct spinlock spl;
static volatile unsigned long counter = 0;

void spinlock_thread_entry(void *arg)
{
	bool incs = get_cpu_nr() % 2;
	for(long i = 0; i < (INT64_MAX); i++)
	{
		spin_lock(&spl);

		if(incs)
			counter++;
		else
			counter--;
		spin_unlock(&spl);
	}
}

void spinlock_test()
{
	unsigned int nr_cpus = get_nr_cpus();
	for(unsigned int i = 0; i < nr_cpus; i++)
	{
		assert(sched_create_thread(spinlock_thread_entry, THREAD_KERNEL, NULL) != NULL);
	}

	printk("Test done.\n");
	assert(counter == 0);
}

#endif

#ifdef CONFIG_KTEST_ALLOC_PAGE_PERF

#include <onyx/clock.h>

void page_alloc_perf(void)
{
	struct clocksource *c = get_main_clock();

	hrtime_t t0 = c->get_ns();

	alloc_page(PAGE_ALLOC_NO_ZERO | (1 << 12));

	hrtime_t t1 = c->get_ns();

	printk("Performance: %lu ns\n", t1 - t0);
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


void do_ktests(void)
{
	size_t nr_tests = sizeof(tests) / sizeof(uintptr_t);

	for(size_t i = 0; i < nr_tests; i++)
	{
		tests[i]();
	}
}

#endif
