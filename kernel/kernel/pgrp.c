/*
* Copyright (c) 2020 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <stdlib.h>
#include <errno.h>

#include <onyx/process.h>

/* TODO: Making this into a hashtable would be a good idea for performance, no? 
 * For now, it's staying as a list_head as a simple way to prototype ideas.
 */
static struct spinlock pgrp_list_lock;
static struct list_head pgrp_list = LIST_HEAD_INIT(pgrp_list);

void pgrp_dtor(struct ref *ref)
{
	struct pgrp *proc = (struct pgrp *) ref;

	for(int i = 0; i < PGRP_MAX; i++)
		assert(list_is_empty(&proc->pgrp_head[i]));

	free(proc);
}

struct pgrp *pgrp_find(pid_t pid)
{
	spin_lock(&pgrp_list_lock);

	struct pgrp *ret = NULL;

	list_for_every(&pgrp_list)
	{
		struct pgrp *pgrp = container_of(l, struct pgrp, pgrp_list_node);

		if(pgrp->id == pid)
		{
			ret = pgrp;
			pgrp_get(pgrp);
			break;
		}
	}

	return ret;
}

struct pgrp *pgrp_create(pid_t pid)
{
	struct pgrp *pgrp = NULL;

	if((pgrp = pgrp_find(pid)) != NULL)
	{
		goto out;
	}

	pgrp = zalloc(sizeof(struct pgrp));
	if(!pgrp)
		return NULL;

	ref_init(&pgrp->refc, 1, pgrp_dtor);

	for(int i = 0; i < PGRP_MAX; i++)
		INIT_LIST_HEAD(&pgrp->pgrp_head[i]);

	pgrp->id = pid;
	list_add_tail(&pgrp->pgrp_list_node, &pgrp_list);

out:
	spin_unlock(&pgrp_list_lock);
	return pgrp;
}

void pgrp_inherit(struct process *proc, struct process *parent)
{
	struct pgrp *session = parent->session;
	struct pgrp *pgrp = parent->pgrp;

	proc->session = session;
	proc->pgrp = pgrp;

	pgrp_get(session);
	pgrp_get(pgrp);

	list_add_tail(&proc->session_list_node, &session->pgrp_head[PGRP_SESSION]);
	list_add_tail(&proc->pgrp_list_node, &pgrp->pgrp_head[PGRP_PROCESS_GROUP]);
}

bool process_is_session_leader(struct process *proc)
{
	return proc->pid == proc->session->id;
}

int sys_setpgid(pid_t pid, pid_t pgid)
{
	int st = 0;
	struct process *dest = NULL;
	struct pgrp *pgrp = NULL;
	/* Okay, so, this should work like setpgid(2), from linux. Check the docs for more information */

	/* If pid is supplied as zero, pid should be the calling process's pid */
	if(pid == 0)
		pid = get_current_process()->pid;

	/* If pgid is 0, pgid is supposed to be the pid */
	if(pgid == 0)
		pgid = pid;
	
	if(pgid < 0)
	{
		st = -EINVAL;
		goto out;
	}

	dest = get_process_from_pid(pid);
	if(!dest && (dest != get_current_process() || dest->parent != get_current_process()))
	{
		st = -ESRCH;
		goto out1;
	}

	if(process_is_session_leader(dest) || dest->session )


	pgrp = pgrp_create(pgid);

out1:
	process_put(dest);
out:
	return st;	
}
