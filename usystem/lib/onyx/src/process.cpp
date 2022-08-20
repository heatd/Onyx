/*
 * Copyright (c) 2021 - 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#include <errno.h>

#include <system_error>
#include <vector>

#include <libonyx/handle.h>
#include <libonyx/process.h>

int onx_process_open(pid_t pid, int flags)
{
    return onx_handle_open(ONX_HANDLE_TYPE_PROCESS, (unsigned long) pid, flags);
}

void onx_process_close(int fd)
{
    onx_handle_close(fd);
}

std::vector<onx::vm_region> onx::get_mm_regions(int handle)
{
    std::vector<char> data;
    std::vector<onx::vm_region> regions;
    size_t vec_size = 0;
    size_t quantity = 0;

    do
    {
        vec_size = quantity;
        data.resize(vec_size);

        auto status = onx_handle_query(handle, data.data(), vec_size, PROCESS_GET_VM_REGIONS,
                                       &quantity, nullptr);

        if (status == -1 && errno != ENOSPC)
        {
            throw std::system_error(errno, std::generic_category());
        }

    } while (vec_size != quantity);

    for (size_t i = 0; i < vec_size;)
    {
        const onx_process_vm_region *reg = (const onx_process_vm_region *) &data[i];
        i += reg->size;

        onx::vm_region region;
        region.length = reg->length;
        region.offset = reg->offset;
        region.protection = reg->protection;
        region.start = reg->start;
        region.mapping_type = reg->mapping_type;

        std::string name = "[anon]";
        if (reg->size - sizeof(onx_process_vm_region) > 0)
        {
            // We have a name! set it
            name = reg->name;
        }

        region.name = std::move(name);

        regions.push_back(std::move(region));
    }

    return regions;
}
