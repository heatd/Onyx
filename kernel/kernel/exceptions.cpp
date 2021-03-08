/*
* Copyright (c) 2019 Pedro Falcato
* This file is part of Carbon, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#include <onyx/exceptions.h>

extern "C" struct exception_table_data _ehtable_start;
extern "C" struct exception_table_data _ehtable_end;

unsigned long exceptions_get_fixup(unsigned long ip)
{
	struct exception_table_data *d = (struct exception_table_data *) &_ehtable_start;
	struct exception_table_data *end = (struct exception_table_data *) &_ehtable_end;

	while(d != end)
	{
		if(d->ip == ip)
			return d->fixup;
		d++;
	}

	return NO_FIXUP_EXISTS;
}
