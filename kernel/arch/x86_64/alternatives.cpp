/*
 * Copyright (c) 2021 - 2026 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include <string.h>

#include <onyx/code_patch.h>
#include <onyx/cpu.h>
#include <onyx/types.h>
#include <onyx/x86/alternatives.h>

#include <onyx/linker_section.hpp>

DEFINE_LINKER_SECTION_SYMS(__start_code_patch, __end_code_patch);
DEFINE_LINKER_SECTION_SYMS(__alternatives_start, __alternatives_end);

static linker_section code_patches{&__start_code_patch, &__end_code_patch};
static linker_section generic_alternatives{&__alternatives_start, &__alternatives_end};

#define ALTERNATIVE_START 0
#define ALTERNATIVE_EOL   -1u

static u8 *do_alternative(u8 *p, unsigned long patch_site)
{
    u32 orig_size = 0, chosen_feature, chosen_size;
    void *chosen_bytes = NULL;

    for (;;)
    {
        u32 feature, size;

        memcpy(&feature, p, sizeof(u32));
        p += sizeof(u32);
        if (feature == ALTERNATIVE_EOL)
            break;
        memcpy(&size, p, sizeof(u32));
        p += sizeof(u32);
        if (feature == ALTERNATIVE_START)
        {
            /* Grab the original code size */
            orig_size = size;
        }

        /* Assume we want the later feature of the bunch. */
        if (feature == ALTERNATIVE_START || x86_has_cap(feature))
        {
            chosen_feature = feature;
            chosen_bytes = p;
            chosen_size = size;
        }

        p += size;
    }

    CHECK(chosen_bytes != NULL);

    if (chosen_feature == ALTERNATIVE_START)
    {
        /* No patching is happening */
        goto out;
    }

    /* orig_size needs to >= chosen_size. Otherwise, we can't patch. */
    if (WARN_ON(orig_size < chosen_size))
        goto out;
    code_patch::replace_instructions((void *) patch_site, chosen_bytes, chosen_size, orig_size);
out:
    return p;
}

static void x86_do_generic_alternatives(void)
{
    auto p = generic_alternatives.start;
    auto end = generic_alternatives.end;
    unsigned long addr;

    while (p < end)
    {
        /* Format for the alternatives:
         * <patch address>
         * <N + 1 tags, where N > 1>
         *  u32 FEATURE;
         *  u32 patch_size;
         *  <patch_size instruction bytes>
         * <N-th tag>
         *  u32 FEATURE = -1;
         * the original code has FEATURE = 0 as a special-case.
         */
        memcpy(&addr, p, sizeof(addr));
        p += sizeof(unsigned long);
        p = do_alternative(p, addr);
    }
}

void x86_do_alternatives()
{
    auto elems = code_patches.size() / sizeof(code_patch_location);
    auto loc = code_patches.as<code_patch_location>();

    for (unsigned long i = 0; i < elems; i++, loc++)
        loc->patching_func(loc);

    x86_do_generic_alternatives();
}
