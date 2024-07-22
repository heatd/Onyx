/*
 * Copyright (c) 2016-2020 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 */
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <onyx/compiler.h>
#include <onyx/dev.h>
#include <onyx/init.h>
#include <onyx/panic.h>
#include <onyx/vm.h>

size_t zero_read(size_t offset, size_t count, void *buf, file *f)
{
    /* While reading from /dev/zero, all you read is zeroes. Just memset the buf. */
    if (user_memset(buf, 0, count) < 0)
        return -EFAULT;

    return count;
}

size_t zero_write(size_t offset, size_t len, void *buf, file *f)
{
    /* Writes behave like /dev/null */
    return len;
}

void *zero_mmap(struct vm_area_struct *area, struct file *node)
{
    vm_make_anon(area);

    if (vm_area_struct_setup_backing(area, vma_pages(area), false) < 0)
        return nullptr;

    return (void *) area->vm_start;
}

const file_ops zero_fileops = {
    .read = zero_read,
    .write = zero_write,
    .mmap = zero_mmap,
};

void zero_init()
{
    auto min = dev_register_chardevs(0, 1, 0, &zero_fileops, "zero");
    if (!min)
        panic("Could not create a character device for /dev/zero!\n");

    min.value()->show(0666);
}

INIT_LEVEL_CORE_KERNEL_ENTRY(zero_init);
