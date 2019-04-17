/*
* Copyright (c) 2018 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <assert.h>

#include <onyx/i2c.h>

int i2c_transaction(struct i2c_adapter *adapter, struct i2c_message *msgs,
		 size_t nr_msgs)
{
	assert(adapter->do_batch_transfer != NULL);

	mutex_lock(&adapter->mtx);

	int st = adapter->do_batch_transfer(adapter, msgs, nr_msgs);

	mutex_unlock(&adapter->mtx);

	return st;
}