/*
* Copyright (c) 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _KERNEL_BINFMT_H
#define _KERNEL_BINFMT_H
#include <stdint.h>

#include <onyx/vfs.h>

struct binfmt_args;
typedef void *(*binfmt_handler_t)(struct binfmt_args *);

struct binfmt
{
	uint8_t *signature;
	size_t size_signature;
	bool (*is_valid_exec)(uint8_t *signature);
	binfmt_handler_t callback;
	struct binfmt *next;
};

struct exec_state;
struct binfmt_args
{
	uint8_t *file_signature;
	char *filename;
	char **argv, **envp;
	int *argc;
	struct file *file;
	char *interp_path;
	bool needs_interp;
	struct exec_state *state;
};

#define BINFMT_SIGNATURE_LENGTH     100

void *bin_do_interp(struct binfmt_args *args);
void *load_binary(struct binfmt_args *);
int install_binfmt(struct binfmt *);

#endif
