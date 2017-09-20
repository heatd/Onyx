/*
* Copyright (c) 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#ifndef _ONYX_ATOMIC_H
#define _ONYX_ATOMIC_H

#include <stdbool.h>

/**********************************************************************************
 * Each and every one of these functions perform basic atomic ops on native-sized
 * words 
***********************************************************************************/

unsigned long atomic_inc(unsigned long *word, unsigned long val);
unsigned long atomic_dec(unsigned long *word, unsigned long val);
unsigned long atomic_or(unsigned long *word, unsigned long val);
unsigned long atomic_and(unsigned long *word, unsigned long val);
unsigned long atomic_xor(unsigned long *word, unsigned long val);
bool atomic_cmp_and_swap(unsigned long *word, unsigned long val, unsigned long oldval);
unsigned long atomic_set(unsigned long *word, unsigned long val);

#endif
