/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>

#include <kernel/log.h>
#include <kernel/timer.h>
#include <kernel/vmm.h>
#include <kernel/panic.h>
#include <drivers/rtc.h>

static char _log_buf[LOG_BUF_SIZE];
static size_t log_position = 0;

void kernlog_print(const char *msg)
{
	if(log_position + strlen(msg) + 13 + 1 <= LOG_BUF_SIZE)
	{
		/* If there's clearly enough space, it's straight forward to do */
		/* Compose a message containing a timestamp */
		memset(&_log_buf[log_position], 0, strlen(msg) + 13 + 2);
		snprintf(&_log_buf[log_position], strlen(msg) + 13 + 2, "[%05u.%05u] %s", get_tick_count() / 1000, get_tick_count() % 1000, msg);
		log_position += strlen(msg) + 13 + 1;
	}
	else
	{
		/* else start overwriting the buffer head */
		log_position = 0;
		snprintf(&_log_buf[log_position], strlen(msg) + 13 + 2, "[%u.%u] %s", get_tick_count() / 1000, get_tick_count() % 1000, msg);
		log_position += strlen(msg) + 13 + 1;
	}
}
void kernlog_clear(void)
{
	memset(_log_buf, 0, LOG_BUF_SIZE);
	log_position = 0;
}
#define SYSLOG_ACTION_READ 		2
#define SYSLOG_ACTION_READ_CLEAR 	4
#define SYSLOG_ACTION_CLEAR		5
int sys_syslog(int type, char *buffer, int len)
{
	if(vmm_check_pointer(buffer, len) < 0)
		return -EFAULT;
	switch(type)
	{
		case SYSLOG_ACTION_READ:
		{
			memcpy(buffer, _log_buf, len);
			break;
		}
		case SYSLOG_ACTION_READ_CLEAR:
		{
			memcpy(buffer, _log_buf, len);
			kernlog_clear();
			break;
		}
		case SYSLOG_ACTION_CLEAR:
		{
			kernlog_clear();
			break;
		}
	}
	return 0;
}
void kernlog_dump(void)
{
	printk("%s\n", _log_buf);
}