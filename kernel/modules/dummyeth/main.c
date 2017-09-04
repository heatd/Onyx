/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <stdlib.h>
#include <stdio.h>

#include <onyx/ethernet.h>
#include <onyx/module.h>

MODULE_AUTHOR("Pedro Falcato");
MODULE_LICENSE(MODULE_LICENSE_MIT);

#define MPRINTF(...) printf("dummyeth: "__VA_ARGS__)

int dummy_send_packet(const void *ptr, uint16_t len)
{
	(void) ptr;
	(void) len;
	return 0;
}

int module_init()
{
	MPRINTF("initializing!\n");
	eth_set_dev_send_packet(dummy_send_packet);
	return 0;
}
int module_fini()
{
	MPRINTF("exiting!\n");
	eth_set_dev_send_packet((device_send_packet)NULL);
	return 0;
}
