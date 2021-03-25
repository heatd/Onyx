/*
* Copyright (c) 2020 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _ONYX_SOFTIRQ_H
#define _ONYX_SOFTIRQ_H

enum softirq_vector
{
	SOFTIRQ_VECTOR_TIMER = 0,
	SOFTIRQ_VECTOR_NETRX
};

void softirq_raise(enum softirq_vector vec);
bool softirq_pending();
void softirq_handle();

#endif
