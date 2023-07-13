/*
 * Copyright (c) 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
#include <onyx/irq.h>
#include <onyx/panic.h>

void halt()
{
    irq_disable();
    while (true)
    {
        __asm__ __volatile__("wfi");
    }

    __builtin_unreachable();
}
