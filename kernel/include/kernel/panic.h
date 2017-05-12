/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _PANIC_H
#define _PANIC_H

#include <multiboot2.h>
#include <kernel/compiler.h>
#include <kernel/registers.h>
ARCH_SPECIFIC void halt();
ARCH_SPECIFIC void get_thread_ctx(registers_t* regs);
/* The functions halt and get_thread_ctx are architecture dependent, as they require manual assembly.
 * As so, its left for the architecture to implement these functions. The kernel expects them to be hooked.
 */
extern __attribute__ ((noreturn,cold,noinline))
void panic(const char* msg);
uintptr_t get_kernel_sym_by_name(char *name);
void init_elf_symbols(struct multiboot_tag_elf_sections *restrict secs);
#endif
