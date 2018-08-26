/*
* Copyright (c) 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <assert.h>
#include <fcntl.h>

#include <sys/user.h>

#include <onyx/process.h>
#include <onyx/scheduler.h>
#include <onyx/mutex.h>
#include <onyx/file.h>
#include <onyx/vfs.h>
#include <onyx/atomic.h>
#include <onyx/proc_event.h>

#include <proc_event.h>

static void __append_to_list(struct proc_event_sub *s, struct process *p)
{
	atomic_inc(&p->nr_subs, 1);

	spin_lock(&p->sub_queue_lock);
	
	struct proc_event_sub **sp = &p->sub_queue;

	while(*sp)
	{
		sp = &((*sp)->next);
	}
	*sp = s;

	spin_unlock(&p->sub_queue_lock);
}

static void __remove_from_list(struct process *p, struct proc_event_sub *s)
{
	spin_lock(&p->sub_queue_lock);
	if(p->sub_queue == s)
	{
		p->sub_queue = s->next;
		spin_unlock(&p->sub_queue_lock);
		return;
	}
	
	for(struct proc_event_sub *i = p->sub_queue; i; i = i->next)
	{
		if(i->next == s)
		{
			i->next = s->next;
			break;
		}
	}

	atomic_dec(&p->nr_subs, 1);
	spin_unlock(&p->sub_queue_lock);
}

size_t proc_event_read(int flags, size_t offset, size_t sizeofread, void* buffer,
	struct inode* file)
{
	struct proc_event_sub *sub = file->i_helper;

	if(sub->valid_sub == false)
	{
		free(sub);
		return errno = ESRCH, (size_t) -1;
	}

	if(!sub->has_new_event && flags & O_NONBLOCK)	return 0;

	sem_wait(&sub->event_semaphore);

	memcpy(buffer, &sub->event_buf, sizeofread);

	atomic_set(&sub->has_new_event, 0);

	return sizeofread;
	
}

void proc_event_close(struct inode *ino)
{
	struct proc_event_sub *sub = ino->i_helper;

	if(sub->valid_sub == false)
	{
		free(sub);
		return;
	}
	
	__remove_from_list(sub->target_process, sub);
}

void proc_event_do_ack(struct process *process);

unsigned int proc_event_ioctl(int request, void *argp, struct inode* ino)
{
	switch(request)
	{
		case PROCEVENT_ACK:
		{
			struct proc_event_sub *sub = ino->i_helper;
			
			if(sub->valid_sub)
			{
				proc_event_do_ack(sub->target_process);
			}
			return 0;
		}
		default:
			return -EINVAL;
	}
}

int sys_proc_event_attach(pid_t pid, unsigned long flags)
{	
	struct proc_event_sub *new_sub = zalloc(sizeof(*new_sub));

	if(!new_sub)
		return -ENOMEM;
	
	new_sub->waiting_thread = get_current_thread();
	new_sub->flags = flags;
	new_sub->next = NULL;
	new_sub->valid_sub = true;
	new_sub->has_new_event = false;

	struct inode *ino = inode_create();
	if(!ino)
	{
		free(new_sub);
		return -ENOMEM;
	}
	
	ino->i_helper = new_sub;
	ino->i_fops.read = proc_event_read;
	ino->i_fops.close = proc_event_close;
	ino->i_fops.ioctl = proc_event_ioctl;
	ino->i_type = VFS_TYPE_UNIX_SOCK;

	struct process *p = get_process_from_pid(pid);
	if(!p)
	{
		free(ino);
		free(new_sub);
		return -ESRCH;
	}
	
	new_sub->target_process = p;

	int fd = open_with_vnode(ino, O_RDWR);
	if(fd < 0)
	{
		free(ino);
		free(new_sub);
		return -errno;
	}

	__append_to_list(new_sub, p);

	return fd;
}

void proc_event_do_ack(struct process *process)
{
	if(__sync_add_and_fetch(&process->nr_acks, 1) == process->nr_subs)
	{
		mutex_lock(&process->condvar_mutex);
		condvar_signal(&process->syscall_cond);
		mutex_unlock(&process->condvar_mutex);
	}
}

void proc_event_enter_syscall(struct syscall_frame *regs, uintptr_t rax)
{
	struct process *current = get_current_process();

	for(struct proc_event_sub *s = current->sub_queue; s; s = s->next)
	{
		s->event_buf.type = PROC_EVENT_SYSCALL_ENTER;
		s->event_buf.pid = current->pid;
		s->event_buf.thread = get_current_thread()->id;
		s->event_buf.e_un.syscall.cs = 0x2b;
		s->event_buf.e_un.syscall.ds = regs->ds;
		s->event_buf.e_un.syscall.eflags = regs->rflags;
		s->event_buf.e_un.syscall.es = regs->ds;
		s->event_buf.e_un.syscall.fs = regs->ds;
		s->event_buf.e_un.syscall.fs_base = (unsigned long) get_current_thread()->fs;
		s->event_buf.e_un.syscall.gs = regs->ds;
		s->event_buf.e_un.syscall.gs_base = (unsigned long) get_current_thread()->gs;
		s->event_buf.e_un.syscall.orig_rax = rax;
		s->event_buf.e_un.syscall.ss = regs->ds;
		s->event_buf.e_un.syscall.r10 = regs->r10;
		s->event_buf.e_un.syscall.r11 = 0;
		s->event_buf.e_un.syscall.r12 = regs->r12;
		s->event_buf.e_un.syscall.r13 = regs->r13;
		s->event_buf.e_un.syscall.r14 = regs->r14;
		s->event_buf.e_un.syscall.r15 = regs->r15;
		s->event_buf.e_un.syscall.rax = rax;
		s->event_buf.e_un.syscall.r8 = regs->r8;
		s->event_buf.e_un.syscall.r9 = regs->r9;
		s->event_buf.e_un.syscall.rsp = (unsigned long) regs->user_rsp;
		s->event_buf.e_un.syscall.rbx = regs->rbx;
		s->event_buf.e_un.syscall.rbp = regs->rbp;
		s->event_buf.e_un.syscall.rcx = regs->r10;
		s->event_buf.e_un.syscall.rdx = regs->rdx;
		s->event_buf.e_un.syscall.rdi = regs->rdi;
		s->event_buf.e_un.syscall.rip = regs->rip;
		s->has_new_event = true;

		sem_signal(&s->event_semaphore);
	}

	if(current->nr_subs == 0)
		return;

	mutex_lock(&current->condvar_mutex);
	condvar_wait(&current->syscall_cond, &current->condvar_mutex);

	current->nr_acks = 0;
	mutex_unlock(&current->condvar_mutex);
}

void proc_event_exit_syscall(long retval, long syscall_nr)
{
	struct process *current = get_current_process();

	for(struct proc_event_sub *s = current->sub_queue; s; s = s->next)
	{
		s->event_buf.type = PROC_EVENT_SYSCALL_EXIT;
		s->event_buf.pid = current->pid;
		s->event_buf.e_un.syscall_exit.retval = retval;
		s->event_buf.e_un.syscall_exit.syscall_nr = syscall_nr;
		s->event_buf.thread = get_current_thread()->id;
		s->has_new_event = true;

		sem_signal(&s->event_semaphore);
	}

	if(current->nr_subs == 0)
		return;

	mutex_lock(&current->condvar_mutex);
	condvar_wait(&current->syscall_cond, &current->condvar_mutex);

	current->nr_acks = 0;
	mutex_unlock(&current->condvar_mutex);

}