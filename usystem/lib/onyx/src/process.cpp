/*
 * Copyright (c) 2021 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 */

#include <errno.h>

#include <libonyx/handle.h>
#include <libonyx/process.h>

int onx_process_open(pid_t pid, int flags)
{
    return onx_handle_open(ONX_HANDLE_TYPE_PROCESS, (unsigned long)pid, flags);
}

void onx_process_close(int fd)
{
    onx_handle_close(fd);
}
