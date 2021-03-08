/*
* Copyright (c) 2021 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _ONYX_HANDLE_H
#define _ONYX_HANDLE_H

#include <onyx/public/handle.h>

class handleable
{
protected:

	virtual int get_info(void *ubuf, size_t len, int flags)
	{
		return -EINVAL;
	}
};

#endif
