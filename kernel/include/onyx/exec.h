/*
 * Copyright (c) 2020 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 */
#ifndef _ONYX_EXEC_H
#define _ONYX_EXEC_H

#include <onyx/vm.h>

#ifdef __cplusplus
struct exec_state
{
    mm_address_space *new_address_space{};
    bool flushed{false};
    ~exec_state()
    {
        if (new_address_space)
            mmput(new_address_space);
    }
};
#else
struct exec_state;
#endif

struct binfmt_args;
__BEGIN_CDECLS
int exec_state_create(struct exec_state *state);
int flush_old_exec(struct binfmt_args *state);
bool file_is_executable(struct file *exec_file);
__END_CDECLS
#endif
