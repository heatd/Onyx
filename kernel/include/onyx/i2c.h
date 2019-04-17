/*
* Copyright (c) 2018 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#ifndef _ONYX_I2C_H
#define _ONYX_I2C_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#include <onyx/mutex.h>

struct i2c_message
{
	uint16_t addr;
	bool write;
	uint8_t *buffer;
	uint32_t length;
	uint32_t transfered;
};

struct i2c_adapter
{
	const char *name;
	struct mutex mtx;
	void *priv;
	int (*do_batch_transfer)(struct i2c_adapter *adapter,
				     struct i2c_message *messages, size_t nr);
};

int i2c_transaction(struct i2c_adapter *adapter, struct i2c_message *msgs,
		 size_t nr_msgs);


#endif