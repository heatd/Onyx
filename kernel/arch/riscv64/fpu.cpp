/*
 * Copyright (c) 2021 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 */

#include <onyx/fpu.h>

// FIXME: STUB
void setup_fpu_area(unsigned char *address)
{
}
void save_fpu(void *address)
{
}
void restore_fpu(void *address)
{
}
void fpu_ptrace_getfpregs(void *fpregs, struct user_fpregs_struct *regs)
{
}
void fpu_init(void)
{
}
size_t fpu_get_save_size(void)
{
    return 0;
}
size_t fpu_get_save_alignment(void)
{
    return 1;
}
