/*
* Copyright (c) 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _UNWIND_H
#define _UNWIND_H

#ifdef __cplusplus
extern "C" {
#endif
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

typedef struct unwind_info
{
	uintptr_t address;
	char *name;
} Unwind_info;
/* Unwinds the stack. Returns the unwind info in a malloc'd Unwind_info. 
   Returns the number of entries of the structure in nr_info */
Unwind_info *Unwind_unwind(size_t *nr_info);
void Unwind_dump(_Bool should_exit, int exitcode);
#ifdef __cplusplus
}
#endif
#endif
