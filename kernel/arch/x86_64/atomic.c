/*
* Copyright (c) 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#include <onyx/atomic.h>

unsigned long atomic_inc(unsigned long *word, unsigned long operand)
{
	unsigned long val =  __sync_add_and_fetch(word, operand);
	__sync_synchronize();
	return val;
}

unsigned long atomic_dec(unsigned long *word, unsigned long operand)
{
	unsigned long val = __sync_sub_and_fetch(word, operand);
	__sync_synchronize();
	return val;
}

unsigned long atomic_or(unsigned long *word, unsigned long operand)
{
	unsigned long val = __sync_or_and_fetch(word, operand);
	__sync_synchronize();
	return val;
}

unsigned long atomic_and(unsigned long *word, unsigned long operand)
{
	unsigned long val = __sync_and_and_fetch(word, operand);
	__sync_synchronize();
	return val;
}

unsigned long atomic_xor(unsigned long *word, unsigned long operand)
{
	unsigned long val = __sync_xor_and_fetch(word, operand);
	__sync_synchronize();
	return val;
}
