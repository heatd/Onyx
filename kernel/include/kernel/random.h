/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _RANDOM_H
#define _RANDOM_H

#include <stddef.h>

void add_entropy(void *ent, size_t size);
void get_entropy(char *buf, size_t s);
void initialize_entropy();
unsigned int get_random_int(void);

#endif