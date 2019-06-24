/*
* Copyright (c) 2019 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#ifndef _KASAN_H
#define _KASAN_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

void kasan_init(void);
int kasan_alloc_shadow(unsigned long addr, size_t size, bool accessible);
void kasan_set_state(unsigned long *ptr, size_t size, int state);

#endif