/*----------------------------------------------------------------------
 * Copyright (C) 2016, 2017 Pedro Falcato
 *
 * This file is part of Onyx, and is made available under
 * the terms of the GNU General Public License version 2.
 *
 * You can redistribute it and/or modify it under the terms of the GNU
 * General Public License version 2 as published by the Free Software
 * Foundation.
 *----------------------------------------------------------------------*/
#ifndef _RANDOM_H
#define _RANDOM_H

#include <stddef.h>

void add_entropy(void *ent, size_t size);
void get_entropy(char *buf, size_t s);
void initialize_entropy();


#endif