/*
* Copyright (c) 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <stdio.h>
#include <stdint.h>

#include <onyx/driver.h>

extern uintptr_t _driver_init_start;
extern uintptr_t _driver_init_end;

void driver_init(void)
{	
	uintptr_t *ptr = &_driver_init_start;
	uintptr_t *end = &_driver_init_end;
	while(ptr != end)
	{
		void(*func)(void) = (void*) *ptr;
		func();
		ptr++;
	}
}
