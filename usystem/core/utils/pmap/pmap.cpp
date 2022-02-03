/*
 * Copyright (c) 2021 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
#include <errno.h>

#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>

#include <libonyx/handle.h>
#include <libonyx/process.h>

int main(int argc, char **argv)
{
    if (argc < 2)
    {
        std::printf("pmap: Bad usage\nUsage: pmap [pid]\n");
        return 1;
    }

    pid_t pid = std::atoi(argv[1]);

    auto handle = onx_process_open(pid, ONX_HANDLE_CLOEXEC);
    if (handle < 0)
    {
        std::perror("onx_process_open");
        return 1;
    }

    std::vector<char> data;
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
            std::perror("onx_handle_query PROCESS_GET_VM_REGIONS");
            return 1;
        }

    } while (vec_size != quantity);

    for (size_t i = 0; i < vec_size;)
    {
        const onx_process_vm_region *reg = (const onx_process_vm_region *) &data[i];
        i += reg->size;
        std::printf("%016lx - %016lx\t", reg->start, reg->start + reg->length);

        std::printf("%s", (reg->protection & VM_REGION_PROT_READ ? "r" : "-"));
        std::printf("%s", (reg->protection & VM_REGION_PROT_WRITE ? "w" : "-"));
        std::printf("%s", (reg->protection & VM_REGION_PROT_EXEC ? "x" : "-"));

        std::string name = "[anon]";
        if (reg->size - sizeof(onx_process_vm_region) > 0)
        {
            // We have a name! set it
            name = reg->name;
        }

        std::cout << " " << name << "\n";
    }

    return 0;
}
