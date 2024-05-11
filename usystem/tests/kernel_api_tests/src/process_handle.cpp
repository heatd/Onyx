/*
 * Copyright (c) 2020 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 */

#include <unistd.h>

#include <string>

#include <gtest/gtest.h>
#include <libonyx/handle.h>
#include <libonyx/process.h>

TEST(ProcHandle, CanOpenHandle)
{
    int handle = onx_process_open(getpid(), ONX_HANDLE_CLOEXEC);

    ASSERT_NE(handle, -1);

    onx_process_close(handle);
}

TEST(ProcHandle, CanGetName)
{
    int handle = onx_process_open(getpid(), ONX_HANDLE_CLOEXEC);
    ASSERT_NE(handle, -1);

    char name_buf[NAME_MAX + 1];
    ASSERT_NE(onx_handle_query(handle, name_buf, NAME_MAX + 1, PROCESS_GET_NAME, nullptr, nullptr),
              -1);
    std::string name{name_buf};
    ASSERT_EQ(name, std::string{"kernel_api_test"});
    onx_process_close(handle);
}
