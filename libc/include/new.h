
#ifndef _NEW_H
#define _NEW_H

inline void* operator new(size_t size, void* p)
{
	(void) size;
	return p;
}

#endif
