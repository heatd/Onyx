/* Copyright 2016 Pedro Falcato

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http ://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
/**************************************************************************
 *
 *
 * File: sbrk.c
 *
 * Description: sbrk(2) implementation
 *
 * Date: 6/3/2016
 *
 *
 **************************************************************************/
#include <stdint.h>
#include <stdint.h>
#include <kernel/mm.h>
static char *data_area_limit;
static char *data_area_start;

void set_data_area(void *data_area)
{
	data_area_start = data_area;
}

int __brk(void *addr)
{

	/* If the new limit is lesser than 0x400000 ( 4 MiB )or bigger than 0xC0000000 ( 3 GiB ), its invalid */
	data_area_limit = addr;
	uint32_t data_area_difference =
	    (uint32_t) data_area_limit - (uint32_t) data_area_start;
	void *mem =
	    kmmap((uint32_t) data_area_start, data_area_difference / 4096,
		  MAP_WRITE|MAP_USER);
	if (!mem)
		return -1;
	return 0;
}

/**
*	Function Name: sbrk(2)
*	Description: Implementaion of sbrk(2). Increments the program's data area for inc bytes, and maps it
*/
void *__sbrk(uint32_t inc)
{
	if (inc == 0)
		return data_area_limit;
	/* Map it */
	uint32_t pages = inc / 4096;
	if (pages == 0)
		pages = 1;

	kmmap(((uint32_t) data_area_limit & 0xFFFFF000), pages,
	      MAP_WRITE);
	__brk(data_area_limit + inc);
	return data_area_limit;
}

void *get_end_data()
{
	return data_area_limit;
}

void *get_start_data()
{
	return data_area_start;
}
