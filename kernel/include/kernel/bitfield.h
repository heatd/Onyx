/*----------------------------------------------------------------------
 * Copyright (C) 2016 Pedro Falcato
 *
 * This file is part of Spartix, and is made available under
 * the terms of the GNU General Public License version 2.
 *
 * You can redistribute it and/or modify it under the terms of the GNU
 * General Public License version 2 as published by the Free Software
 * Foundation.
 *----------------------------------------------------------------------*/
/**************************************************************************
 *
 *
 * File: bitfield.h
 *
 * Description: Contains macros for bitsetting and other things,useful for bitmaps
 *
 * Date: 30/1/2016
 *
 *
 **************************************************************************/
#ifndef _BITFIELD_H
#define _BITFIELD_H
#define SET_BIT(x,y) \
x |= (1 << y)

#define CLEAR_BIT(x,y) \
x &= ~(1 << y)

#define TOGGLE_BIT(x,y) \
x ^= (1 << y)

#define TEST_BIT(x,y) \
x & (1 << y)
#endif
