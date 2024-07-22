/*
 * Copyright (c) 2016, 2017 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 */
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "stdio_impl.h"
FILE *fopen(const char *path, const char *mode)
{
    return __stdio_open(path, mode);
}
