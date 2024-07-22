/*
 * Copyright (c) 2020 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 */
#ifndef _ONYX_EXEC_H
#define _ONYX_EXEC_H

#include <onyx/vm.h>

struct exec_state
{
    ref_guard<mm_address_space> new_address_space{};
    bool flushed{false};
};

int exec_state_create(struct exec_state *state);

int flush_old_exec(struct exec_state *state);

bool file_is_executable(struct file *exec_file);

#endif
