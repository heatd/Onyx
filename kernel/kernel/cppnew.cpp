/*
 * Copyright (c) 2017 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 */
/********************************************************************************
 *
 *	File: cppnew.c
 *	Description: C++ new/delete implementations
 *
 ********************************************************************************/
#include <stdint.h>
#include <stdlib.h>

void* operator new(size_t size)
{
    return malloc(size);
}

void* operator new[](size_t size)
{
    return malloc(size);
}

void operator delete(void* addr)
{
    return free(addr);
}

void operator delete[](void* addr)
{
    return free(addr);
}

void operator delete(void* ptr, size_t addr)
{
    free(ptr);
}

void operator delete[](void* ptr, size_t addr)
{
    free(ptr);
}
