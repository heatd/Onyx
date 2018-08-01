/*
* Copyright (c) 2018 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <string.h>

#include <onyx/copy.h>

void set_non_temporal_generic(void *d, int b, size_t count)
{
	memset(d, b, count);
}

weak_alias(set_non_temporal_generic, __set_non_temporal)

void copy_non_temporal_generic(void *d, void *s, size_t count)
{
	memcpy(d, s, count);
}

weak_alias(copy_non_temporal_generic, __copy_non_temporal)
