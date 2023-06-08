/*
 * Copyright (c) 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
#include <onyx/page.h>
#include <onyx/vm.h>

#include "ktsan.h"

kt_event_log *kt_event_log_alloc()
{
    // kt_event_log is huge and needs vmalloc
    return (kt_event_log *) vmalloc(vm_size_to_pages(sizeof(kt_event_log)), VM_TYPE_REGULAR,
                                    VM_WRITE | VM_READ,
                                    GFP_KERNEL | PAGE_ALLOC_NO_SANITIZER_SHADOW);
}

void kt_event_log_replay_stack(struct kt_event_log *log, u64 clock, u16 expected_event_type,
                               u64 expected_data, kt_stack *stack)
{
    // Given a clock, expected event, expected data, attempt to replay the stack onto the kt_stack
    // we were given.
    scoped_lock g{log->lock};
    stack->size = 0;

    auto pos = (clock - 1) & KT_EVENT_LOG_MASK;
    auto first = log->buf[pos];

    // This is not the correct event, so this was overrun, oh no!
    if (first >> 48 != expected_event_type || KT_EVENT_DATA(first) != expected_data)
        return;

    int func_exit_deep = 0;

    while (pos != (log->wr & KT_EVENT_LOG_MASK))
    {
        auto val = log->buf[pos];
        u16 event_type = val >> 48;
        if (event_type == 0)
        {
            // Bad event, break
            break;
        }

        if (event_type == KT_EVENT_FUNC_EXIT)
            func_exit_deep++;
        else if (event_type == KT_EVENT_FUNC_ENTRY)
        {
            if (func_exit_deep > 0)
                func_exit_deep--;
            else
            {
                if (stack->size == KT_STACK_NR_PCS)
                    break;
                stack->pcs[stack->size++] = (u64) kt_decompress_ptr(KT_EVENT_DATA(val));
            }
        }

        pos--;
        pos &= KT_EVENT_LOG_MASK;
    }
}
