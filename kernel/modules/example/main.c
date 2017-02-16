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
/* example - An example of a simple kernel module for Onyx */

#include <stdio.h>

#include <kernel/module.h>

MODULE_AUTHOR("Pedro Falcato");
MODULE_LICENSE(MODULE_LICENSE_GPL2);

int module_init()
{
	printf("Module loaded!\n");
	return 0;
} 
int module_fini()
{
	printf("Module unloaded!\n");
	return 0;
}