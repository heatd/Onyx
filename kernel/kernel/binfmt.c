/*
* Copyright (c) 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include <kernel/binfmt.h>

static struct binfmt *format_list = NULL;
void *load_binary(struct binfmt_args *args)
{
	struct binfmt *f = format_list;
	for(; f; f = f->next)
	{
		if(f->is_valid_exec(args->file_signature))
		{
			/* We found the binary, load it */
			return f->callback(args);
		}
	}
	return NULL;
}
int install_binfmt(struct binfmt *format)
{
	if(!format_list)
		format_list = format;
	else
	{
		struct binfmt *f = format_list;
		for(; f->next != NULL; f = f->next);
		f->next = format;
	}
	return 0;
}
