/*
 * Copyright (c) 2021 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
#include <onyx/x86/alternatives.h>

#include <onyx/linker_section.hpp>

DEFINE_LINKER_SECTION_SYMS(__start_code_patch, __end_code_patch);

linker_section code_patches{&__start_code_patch, &__end_code_patch};

void x86_do_alternatives()
{
    auto elems = code_patches.size() / sizeof(code_patch_location);
    auto loc = code_patches.as<code_patch_location>();

    for (unsigned long i = 0; i < elems; i++, loc++)
    {
        loc->patching_func(loc);
    }
}
