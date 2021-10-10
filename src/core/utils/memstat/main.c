/*
* Copyright (c) 2019 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#define _GNU_SOURCE
#include <stdio.h>
#include <limits.h>
#include <unistd.h>

#include <sys/syscall.h>
#include <onyx/public/memstat.h>

int main(int argc, char **argv)
{
	struct memstat stat;
	int st = syscall(SYS_memstat, &stat);
	if(st < 0)
	{
		perror("memstat");
		return 1;
	}

	printf("Memory statistics:\n");
	printf("Total memory: %lu pages(%lu bytes)\n", stat.total_pages, stat.total_pages * PAGESIZE);
	printf("Used memory: %lu pages(%lu bytes)\n", stat.allocated_pages, stat.allocated_pages * PAGESIZE);
	unsigned long free_pages = stat.total_pages - stat.allocated_pages;
	printf("Free memory: %lu pages(%lu bytes)\n", free_pages, free_pages * PAGESIZE);
	printf("Page cache memory: %lu pages(%lu bytes)\n", stat.page_cache_pages, stat.page_cache_pages * PAGESIZE);
	printf("Kernel heap memory: %lu pages(%lu bytes)\n", stat.kernel_heap_pages, stat.kernel_heap_pages * PAGESIZE);

	double memory_pressure = (double) stat.allocated_pages / (double) stat.total_pages;
	printf("Memory pressure: %f(%f%%)\n", memory_pressure, memory_pressure * 100);

	double ratios[3];
	ratios[0] = (double) stat.page_cache_pages / (double) stat.allocated_pages;
	ratios[1] = (double) stat.kernel_heap_pages / (double) stat.allocated_pages;
	ratios[2] = (double) (stat.allocated_pages - (stat.kernel_heap_pages + stat.page_cache_pages))
		/ (double) stat.allocated_pages;

	printf("Allocated memory ratios(page cache - kernel heap - other): %f-%f-%f\n",
		ratios[0], ratios[1], ratios[2]);
	
	return 0;

}