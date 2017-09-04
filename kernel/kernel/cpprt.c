/*
* Copyright (c) 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
/********************************************************************************
 *
 *	File: cpprt.c
 *	Description: C++ runtime support
 *
 ********************************************************************************/
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>

#include <onyx/panic.h>
/* Gets called when a virtual function isn't found */
void __cxa_pure_virtual(void)
{
	/* Just panic */
	panic("__cxa_pure_virtual: Virtual function not found!");
}
/* guard variables */
 
/* The ABI requires a 64-bit type.  */
__extension__ typedef int __guard __attribute__((mode(__DI__)));
 
int __cxa_guard_acquire (__guard *);
void __cxa_guard_release (__guard *);
void __cxa_guard_abort (__guard *);

int __cxa_guard_acquire(__guard *g) 
{
	return !*(char *)(g);
}

void __cxa_guard_release(__guard *g)
{
	*(char *)g = 1;
}

void __cxa_guard_abort(__guard *g)
{

}
