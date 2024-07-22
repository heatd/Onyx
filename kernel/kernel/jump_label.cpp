/*
 * Copyright (c) 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <onyx/code_patch.h>
#include <onyx/mutex.h>
#include <onyx/scoped_lock.h>
#include <onyx/static_key.h>

#include <platform/jump_label.h>

#include <onyx/linker_section.hpp>

DEFINE_LINKER_SECTION_SYMS(__jump_label_start, __jump_label_end);
static linker_section jump_labels{&__jump_label_start, &__jump_label_end};

static void jump_label_patch(struct jump_label *label);

/**
 * @brief Init all jump labels - must run very early in boot, before we hit any label (will fault or
 * do the wrong thing).
 *
 */
void jump_label_init()
{
    auto ptr = jump_labels.as<struct jump_label>();
    auto elems = jump_labels.size() / sizeof(struct jump_label);

    for (unsigned long i = 0; i < elems; i++, ptr++)
    {
        struct static_key *key = jump_label_key(ptr);
        if ((jump_label_polarity(ptr) == JUMP_LABEL_JMP_IF_TRUE && key->val > 0) ||
            (jump_label_polarity(ptr) == JUMP_LABEL_JMP_IF_FALSE && key->val <= 0))
        {
            jump_label_patch(ptr);
        }
        else
        {
            code_patch::nop_out((void *) ptr->ip, JUMP_LABEL_BRANCH_SIZE);
        }
    }
}

static void jump_label_patch(struct jump_label *label)
{
    unsigned char buf[JUMP_LABEL_BRANCH_SIZE];
    size_t seq_size = jump_label_gen_branch(label, buf);
    code_patch::replace_instructions((void *) label->ip, buf, seq_size, JUMP_LABEL_BRANCH_SIZE);
}

/* Protects against concurrent enables/disables of static keys.
 * Note that the current data structure/locking scheme may be slow, but I don't expect static keys
 * to undergo many changes at runtime (hence static).
 */
static mutex jump_label_mutex;

void jump_label_patch_branch(struct static_key *key, bool en)
{
    scoped_mutex g{jump_label_mutex};

    if ((en && key->val == 0) || (!en && key->val > 0))
    {
        // Stale value! just do nothing
        return;
    }

    auto ptr = jump_labels.as<struct jump_label>();
    auto elems = jump_labels.size() / sizeof(struct jump_label);

    for (unsigned long i = 0; i < elems; i++, ptr++)
    {
        if (jump_label_key(ptr) != key)
            continue;
        if ((jump_label_polarity(ptr) == JUMP_LABEL_JMP_IF_TRUE && key->val > 0) ||
            (jump_label_polarity(ptr) == JUMP_LABEL_JMP_IF_FALSE && key->val == 0))
        {
            jump_label_patch(ptr);
        }
        else
        {
            code_patch::nop_out((void *) ptr->ip, JUMP_LABEL_BRANCH_SIZE);
        }
    }
}
