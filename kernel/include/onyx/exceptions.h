/*
 * Copyright (c) 2019 Pedro Falcato
 * This file is part of Carbon, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 */
#ifndef _CARBON_EXCEPTIONS_H
#define _CARBON_EXCEPTIONS_H

struct exception_table_data
{
    unsigned long ip;
    unsigned long fixup;
};

#define NO_FIXUP_EXISTS (unsigned long) -1
unsigned long exceptions_get_fixup(unsigned long ip);

#endif
