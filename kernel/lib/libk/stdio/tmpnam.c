/*
 * Copyright (c) 2016, 2017 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 */
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char *prefix = "/tmp/";
static char tmpnambuf[250];
char *tmpnam(char *s)
{
    memset(tmpnambuf, 0, 250);
    strcpy(tmpnambuf, prefix);
    for (int i = 0; i < 10; i++)
    {
        int c = rand() & 0x7F;
        while (isalnum(c) == 0)
        {
            c = rand() & 0x7F;
        }
        tmpnambuf[strlen(tmpnambuf)] = c;
    }
    if (s)
    {
        strcpy(s, tmpnambuf);
    }
    return tmpnambuf;
}
