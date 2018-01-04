/*
* Copyright (c) 2018 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#include <stdio.h>

#include <onyx/compiler.h>
#include <onyx/page.h>
#include <onyx/panic.h>

#ifdef CONFIG_DO_TESTS

#ifdef CONFIG_KTEST_PAGE_ALLOC

/* Tests the page allocator by dumping every page */
void test_page_alloc(void)
{
	void *ptr = __alloc_page(0);

	for(; ptr; ptr = __alloc_page(0))
	{
		printf("Page: %p\n", ptr);
	}
	halt();
}

#endif

void (*tests[])(void) = {
#ifdef CONFIG_KTEST_PAGE_ALLOC
	test_page_alloc,
#endif
};


__init void do_ktests(void)
{
	size_t nr_tests = sizeof(tests) / sizeof(uintptr_t);

	for(size_t i = 0; i < nr_tests; i++)
	{
		tests[i]();
	}
}

#endif
