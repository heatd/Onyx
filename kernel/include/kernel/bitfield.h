/* Copyright 2016 Pedro Falcato

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http ://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
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
