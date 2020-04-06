/*
* Copyright (c) 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <stdlib.h>
#include <unwind.h>
#include <stdio.h>
#include "internal.h"

/* This file should just contain wrappers around the underlying API */
Unwind_info *Unwind_unwind(size_t *nr_info)
{
	return Unwind_stack(nr_info);
}

void Unwind_dump(_Bool should_exit, int exitcode)
{
	printf("Stack dump:\n");
	size_t nr;
	Unwind_info *unwd = Unwind_unwind(&nr);
	for(size_t i = 0; i < nr; i++)
	{
		printf("           %s\n", unwd[i].name);
	}
	if(should_exit)
		exit(exitcode);
}
