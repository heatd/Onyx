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
#ifndef _SYS_UTSNAME_H
#define _SYS_UTSNAME_H

#define _UTSNAME_LENGTH 100

struct utsname 
{
	char sysname[_UTSNAME_LENGTH];    /* Operating system name (e.g., "Linux") */
	char nodename[_UTSNAME_LENGTH];   /* Name within "some implementation-defined
                                     network" */
	char release[_UTSNAME_LENGTH];    /* Operating system release (e.g., "2.6.28") */
	char version[_UTSNAME_LENGTH];    /* Operating system version */
	char machine[_UTSNAME_LENGTH];    /* Hardware identifier */
	#ifdef _GNU_SOURCE
	char domainname[_UTSNAME_LENGTH]; /* NIS or YP domain name */
	#endif
};







#endif