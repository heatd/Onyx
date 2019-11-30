/*
* Copyright (c) 2019 Pedro Falcato
* This file is part of Carbon, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#ifndef _CARBON_NEW_H
#define _CARBON_NEW_H

inline void *operator new(size_t s, void *ptr)
{
	return ptr;
}

inline void *operator new[](size_t s, void *ptr)
{
	return ptr;
}

inline void operator delete(void *, void *) {}
inline void operator delete[](void *, void *) {}

#endif