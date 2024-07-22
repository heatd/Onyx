/*
 * Copyright (c) 2017 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 */

#ifndef _ONYX_DEBUG_H_
#define _ONYX_DEBUG_H_

/* Nifty trick that allows us to basically hang the kernel until gdb is attached,
 * and then, we just set __gdb_debug_counter to 1
 */

/* TODO: Provide a script to set this variable in gdb? */
#define EARLY_BOOT_GDB_DELAY              \
    volatile int __gdb_debug_counter = 0; \
    while (__gdb_debug_counter != 1)

#endif
