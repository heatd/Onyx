/*
 * Copyright (c) 2021 - 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef _LIBONYX_PROCESS_H
#define _LIBONYX_PROCESS_H

#include <unistd.h>

#include <uapi/process.h>

#ifdef __cplusplus
extern "C"
{
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

#ifdef __cplusplus

#include <string>
#include <vector>

namespace onx
{

struct vm_region
{
    uint64_t start;
    uint64_t length;

    uint32_t protection;
    uint32_t mapping_type;
    uint64_t offset;

    // sha256 hash of the pointer
    unsigned char vmo_identifier[32];
    std::string name;
};

std::vector<onx::vm_region> get_mm_regions(int handle);

} // namespace onx

#endif

#endif
