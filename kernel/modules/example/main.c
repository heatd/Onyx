/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
/* example - An example of a simple kernel module for Onyx */

#include <stdio.h>

#include <kernel/module.h>

MODULE_AUTHOR("Pedro Falcato");
MODULE_LICENSE(MODULE_LICENSE_MIT);

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