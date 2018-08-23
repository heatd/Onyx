/*
* Copyright (c) 2018 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _ONYX_ASYNC_IO_H
#define _ONYX_ASYNC_IO_H

#include <onyx/clock.h>
#include <onyx/semaphore.h>

enum aio_status
{
	AIO_STATUS_OK = 0,
	AIO_STATUS_EIO = 1,
	AIO_STATUS_ETIMEOUT = 2
};

struct aio_req
{
	uint64_t req_start;
	uint64_t req_end;
	enum aio_status status;
	struct semaphore wake_sem;
	void *cookie;
};

#endif