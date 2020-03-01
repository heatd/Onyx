/*
* Copyright (c) 2020 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#include <errno.h>
#include <stdio.h>

#include <onyx/binfmt.h>


void *shebang_load(struct binfmt_args *args)
{
	return NULL;
}

bool shebang_is_valid(uint8_t *signature)
{
	return true;
}

struct binfmt shebang_binfmt = {
	.signature = (unsigned char *) "#!",
	.size_signature = 2,
	.callback = shebang_load,
	.is_valid_exec = shebang_is_valid,
	.next = NULL
};

__init void __elf_init()
{
	install_binfmt(&shebang_binfmt);
}
