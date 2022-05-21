/*
 * Copyright (c) 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
#include <onyx/ktrace.h>

namespace ktrace
{

/**
 * @brief Initialise the ktrace listener
 *
 * @param buffer_length Length of the event buffer
 * @return 0 on success, negative error codes.
 */
int ktrace_listener::init(size_t buffer_length)
{
    if (buffer_length & (PAGE_SIZE - 1))
        return -EINVAL;
    vmo_ = vmo_create_phys(buffer_length);
    if (!vmo_)
        return -ENOMEM;

    buffer_ = vm_map_vmo(VM_KERNEL, VM_TYPE_REGULAR, buffer_length >> PAGE_SHIFT,
                         VM_WRITE | VM_READ, vmo_);
    if (!buffer_)
    {
        vmo_destroy(vmo_);
        vmo_ = nullptr;
        return -ENOMEM;
    }

    return 0;
}

void ktrace_listener::put_data(const ktrace_entry *entry, size_t length)
{
}

} // namespace ktrace
