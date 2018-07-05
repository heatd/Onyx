/*
* Copyright (c) 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include <onyx/binfmt.h>

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

void *bin_do_interp(struct binfmt_args *_args)
{
	struct binfmt_args args;
	memcpy(&args, _args, sizeof(struct binfmt_args));

	struct inode *file = open_vfs(get_fs_root(), args.interp_path);
	if(!file)
	{
		printk("Could not open %s\n", args.interp_path);
		perror("open_vfs");
		while(1);
		return NULL;
	}

	read_vfs(0, 0, 100, args.file_signature, file);

	args.filename = args.interp_path;
	args.interp_path = NULL;
	args.needs_interp = false;
	args.file = file;

	return load_binary(&args);
}
