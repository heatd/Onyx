/*
 * Copyright (c) 2016, 2017 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 */
#include <stdio.h>

#include "stdio_impl.h"
int fclose(FILE *file)
{
    return __stdio_close(file);
}
