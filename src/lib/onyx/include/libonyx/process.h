/*
* Copyright (c) 2021 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _LIBONYX_PROCESS_H
#define _LIBONYX_PROCESS_H

#include <unistd.h>

#include <onyx/public/process.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Opens a process based on \p pid and returns a handle to it.
 * 
 * @param pid Process ID
 * @param flags 
 * @return int A handle to the process, fd style.
 */
int onx_process_open(pid_t pid, int flags);

/**
 * @brief Closes the process handle.
 * 
 * 
 * NOTE: Conceptually, this does the same thing as onx_handle_close(), but is black-boxed
 * for extensibility reasons.
 * 
 * @param fd The handle
 */
void onx_process_close(int fd);

#ifdef __cplusplus
}
#endif

#endif
