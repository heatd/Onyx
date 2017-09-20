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

bool atomic_cmp_and_swap(unsigned long *word, unsigned long val, unsigned long oldval)
{
	bool b = __sync_bool_compare_and_swap(word, oldval, val);
	__sync_synchronize();
	return b;
}

unsigned long atomic_set(unsigned long *word, unsigned long operand)
{
	unsigned long val = __sync_lock_test_and_set(word, operand);
	__sync_synchronize();
	return val;
}
