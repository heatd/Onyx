/*
* Copyright (c) 2019 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#include <onyx/driver.h>

int ehci_init();

int usb_main()
{
	return ehci_init();	
}


DRIVER_INIT(usb_main);
