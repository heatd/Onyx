/*
* Copyright (c) 2020 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _ONYX_CRED_H
#define _ONYX_CRED_H

#include <onyx/rwlock.h>

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

struct creds
{
	struct rwlock lock;
	uid_t ruid;
	uid_t euid;
	gid_t rgid;
	gid_t egid;
	uid_t suid;
	uid_t sgid;
};

struct process;

struct creds *creds_get(void);
struct creds *__creds_get(struct process *p);
struct creds *creds_get_write(void);
struct creds *__creds_get_write(struct process *p);
void creds_put(struct creds *c);
void creds_put_write(struct creds *c);


int process_inherit_creds(struct process *new_child, struct process *parent);

#ifdef __cplusplus
}
#endif

#endif