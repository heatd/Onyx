/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
/**************************************************************************
 *
 *
 * File: bootmem.c
 *
 * Description: Contains the implementation of the kernel's boot memory manager
 *
 * Date: 4/12/2016
 *
 *
 **************************************************************************/

#include <stdio.h>
#include <string.h>
#include <stdbool.h>

#include <multiboot2.h>

#include <onyx/panic.h>
#include <onyx/bootmem.h>
#include <onyx/paging.h>
#include <onyx/panic.h>
#include <onyx/page.h>

void *(*alloc_boot_page_func)(size_t nr_pgs, long flags);

void set_alloc_boot_page(void * (*f)(size_t nr, long flags))
{
	alloc_boot_page_func = f;
}

void *alloc_boot_page(size_t nr_pgs, long flags)
{
	if(!alloc_boot_page_func)
	{
		printf("Early boot panic: No alloc_boot_page");
		halt();
	}

	void *ret = alloc_boot_page_func(nr_pgs, flags);

	if(ret != NULL)
	{
		/*printf("alloc_boot_page: allocated boot pages from %p to %lx (%lu pages)\n", ret,
			(uintptr_t) ret + (nr_pgs << PAGE_SHIFT), nr_pgs); */
	}
	else
	{
		printf("Alloc boot page failed\n");
		while(1);
	}

	return ret;
}