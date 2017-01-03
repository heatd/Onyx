/*----------------------------------------------------------------------
 * Copyright (C) 2016, 2017 Pedro Falcato
 *
 * This file is part of Spartix, and is made available under
 * the terms of the GNU General Public License version 2.
 *
 * You can redistribute it and/or modify it under the terms of the GNU
 * General Public License version 2 as published by the Free Software
 * Foundation.
 *----------------------------------------------------------------------*/
#include <partitions.h>
#include <stdio.h>
static volatile fs_handler code_handlers[0xFF];

void part_add_handler(uint8_t part_code, fs_handler handler)
{
	code_handlers[part_code] = handler;
}
fs_handler lookup_handler_from_partition_code(uint8_t part_code)
{
	return code_handlers[part_code];
}
