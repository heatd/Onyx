/*
* Copyright (c) 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#ifndef _KERNEL_BINFMT_ELF64_H
#define _KERNEL_BINFMT_ELF64_H

#include <kernel/binfmt.h>
#include <kernel/elf.h>

void *elf64_load(struct binfmt_args *args, Elf64_Ehdr *header);

#endif
