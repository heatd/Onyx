/*
 * Copyright (c) 2019 Pedro Falcato
 * This file is part of Carbon, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 */
#ifndef _CARBON_EXCEPTIONS_H
#define _CARBON_EXCEPTIONS_H

#include <onyx/compiler.h>

struct exception_table_data
{
    unsigned long ip;
    unsigned long fixup;
};

__BEGIN_CDECLS

#define NO_FIXUP_EXISTS (unsigned long) -1
unsigned long exceptions_get_fixup(unsigned long ip);

__END_CDECLS

#endif
