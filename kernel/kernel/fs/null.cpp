/*
 * Copyright (c) 2016, 2017 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 */
#include <stdlib.h>
#include <string.h>

#include <onyx/compiler.h>
#include <onyx/dev.h>
#include <onyx/init.h>
#include <onyx/panic.h>

size_t null_write(size_t offset, size_t count, void *buf, file *n)
{
    /* While writing to /dev/null, everything gets discarded. It's a no-op. */
    UNUSED(offset);
    UNUSED(count);
    UNUSED(buf);
    UNUSED(n);
    return count;
}

size_t null_read(size_t offset, size_t len, void *buf, file *f)
{
    /* All reads return EOF */
    UNUSED(offset);
    UNUSED(len);
    UNUSED(buf);
    UNUSED(f);
    return 0;
}

const struct file_ops null_ops = {.read = null_read, .write = null_write};

void null_init(void)
{
    auto dev = dev_register_chardevs(0, 1, 0, &null_ops, cul::string{"null"});
    if (!dev)
        panic("Could not create a device for /dev/null!\n");

    dev.value()->show(0666);
}

INIT_LEVEL_CORE_KERNEL_ENTRY(null_init);
