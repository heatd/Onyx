/*
 * Copyright (c) 2016, 2017 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 */
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

int fprintf(FILE* file, const char* string, ...)
{
    va_list varg;
    va_start(varg, string);
    char buffer[strlen(string) + 250];
    vsprintf(buffer, string, varg);
    va_end(varg);
    return fwrite((const void*) &buffer, strlen(buffer), sizeof(char), file);
}
