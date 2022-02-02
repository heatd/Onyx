/*
 * Copyright (c) 2021 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 */

#include <stdint.h>

#include <onyx/linker_section.hpp>

namespace runtime
{

DEFINE_LINKER_SECTION_SYMS(__init_array_start, __init_array_end);
linker_section init_array_section{&__init_array_start, &__init_array_end};

using ctor = void (*)();

extern "C" void runtime_call_constructors()
{
    ctor *ctors = init_array_section.as<ctor>();
    auto elems = init_array_section.size() / sizeof(ctor);

    for (size_t i = 0; i < elems; i++)
    {
        ctor ct = *(ctors + i);

        if (!ct || ct == (ctor)-1)
            continue;

        ct();
    }
}

} // namespace runtime
