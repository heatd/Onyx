/*
 * Copyright (c) 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
#include <cxxabi.h>

extern "C" char *demangle(const char *name, int *status)
{
    return abi::__cxa_demangle(name, nullptr, nullptr, status);
}
