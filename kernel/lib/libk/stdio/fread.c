/*
 * Copyright (c) 2016, 2017 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 */
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "stdio_impl.h"
size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream)
{
    return __stdio_read(ptr, size, nmemb, stream);
}
