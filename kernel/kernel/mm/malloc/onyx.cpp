/*
 * Copyright (c) 2021 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 */

#include <onyx/vm.h>

extern "C"
{

void *__vmalloc(size_t len)
{
    return vmalloc(vm_size_to_pages(len), VM_TYPE_REGULAR, VM_WRITE | VM_READ);
}

void __vmunmap(void *addr, size_t len)
{
    vfree(addr, vm_size_to_pages(len));
}
}
