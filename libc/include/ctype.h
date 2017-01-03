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
#ifndef _CTYPE_H
#define _CTYPE_H

int tolower(int c);
int toupper(int c);
int _tolower(int c);
int _toupper(int c);
int tonum(int c);
int isnum(int c);
int isalnum(int c);
#endif
