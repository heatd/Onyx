/*
* Copyright (c) 2020 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <errno.h>

#include <onyx/compiler.h>
#include <onyx/cred.h>
#include <onyx/process.h>
#include <onyx/cred.h>

static struct creds kernel_creds = 
{
	.euid = 0,
	.ruid = 0,
	.rgid = 0,
	.egid = 0
};

static struct creds *get_default_creds(void)
{
	struct process *p = get_current_process();
	struct creds *c = &kernel_creds;
	if(likely(p))
	{
		c = &p->cred;
	}

	return c;
}

struct creds *creds_get(void)
{
	struct creds *c = get_default_creds();

	rw_lock_read(&c->lock);
	return c;
}

struct creds *creds_get_write(void)
{
	struct creds *c = get_default_creds();

	rw_lock_write(&c->lock);
	return c;
}

void creds_put(struct creds *c)
{
	rw_unlock_read(&c->lock);
}

void creds_put_write(struct creds *c)
{
	rw_unlock_write(&c->lock);
}

int process_inherit_creds(struct process *new_child, struct process *parent)
{
	/* FIXME: Setuid and setgid? */
	struct creds *parentc = &parent->cred;

	new_child->cred.egid = parentc->egid;
	new_child->cred.rgid = parentc->rgid;
	new_child->cred.euid = parentc->euid;
	new_child->cred.ruid = parentc->ruid;
	/* FIXME: Implement sgid and suid */
	new_child->cred.sgid = new_child->cred.suid = 0;

	return 0;
}

int sys_setuid(uid_t uid)
{
	int st = 0;
	struct creds *c = creds_get_write();

	if(c->euid != 0 && (uid != c->ruid && uid != c->suid))
	{
		st = -EPERM;
		goto out;
	}
	
	if(c->euid == 0)
	{
		c->euid = uid;
		c->ruid = uid;
		c->suid = uid;
	}
	else
	{
		if(uid != c->ruid && uid != c->suid)
		{
			st = -EPERM;
			goto out;
			return -EPERM;
		}

		c->euid = uid;
	}

out:
	creds_put_write(c);

	return st;
}

int sys_setgid(gid_t gid)
{
	int st = 0;
	struct creds *c = creds_get_write();

	if(c->egid != 0 && (gid != c->rgid && gid != c->sgid))
	{
		st = -EPERM;
		goto out;
	}
	
	if(c->egid == 0)
	{
		c->egid = gid;
		c->rgid = gid;
		c->sgid = gid;
	}
	else
	{
		if(gid != c->rgid && gid != c->sgid)
		{
			st = -EPERM;
			goto out;
		}

		c->egid = gid;
	}

out:
	creds_put_write(c);

	return st;
}

uid_t sys_getuid(void)
{
	struct creds *c = creds_get();

	uid_t u = c->ruid;

	creds_put(c);

	return u;
}

gid_t sys_getgid(void)
{
	struct creds *c = creds_get();

	gid_t g = c->rgid;

	creds_put(c);

	return g;
}

/* TODO: Implement set/getresuid, set/getresgid, set/getgroups */