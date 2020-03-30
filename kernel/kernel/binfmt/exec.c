/*
* Copyright (c) 2020 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#include <errno.h>
#include <string.h>
#include <stdio.h>

#include <onyx/binfmt.h>
#include <onyx/exec.h>
#include <onyx/process.h>
#include <onyx/file.h>
#include <onyx/vdso.h>
#include <onyx/random.h>
#include <onyx/user.h>
#include <onyx/signal.h>

void exec_state_destroy(struct exec_state *);

char **process_copy_envarg(char **envarg, bool to_kernel, int *count)
{
	/* Copy the envp/argv to another buffer */
	/* Each buffer takes up argc * sizeof pointer + string_size + one extra pointer(to NULL terminate) */
	size_t nr_args = 0;
	size_t string_size = 0;
	char **b = envarg;
	while(*b)
	{
		string_size += strlen(*b) + 1;
		nr_args++;
		b++;
	}

	size_t buffer_size = (nr_args + 1) * sizeof(void*) + string_size;
	char *new;
	if(to_kernel)
	{
		new = zalloc(buffer_size);
		if(!new)
			return NULL;
	}
	else
	{
		new = get_user_pages(VM_TYPE_SHARED,
			vm_align_size_to_pages(buffer_size), VM_WRITE | VM_NOEXEC | VM_USER);
		if(!new)
			return NULL;
	}

	char *strings = (char*) new + (nr_args + 1) * sizeof(void*);
	char *it = strings;
	/* Actually copy the buffer */
	for(size_t i = 0; i < nr_args; i++)
	{
		strcpy(it, envarg[i]);
		it += strlen(envarg[i]) + 1;
	}
	char **new_args = (char**) new;
	for(size_t i = 0; i < nr_args; i++)
	{
		new_args[i] = (char*) strings;
		strings += strlen(new_args[i]) + 1;
	}
	if(count)
		*count = nr_args;
	return new_args;
}

void *process_setup_auxv(void *buffer, struct process *process)
{
	process->vdso = map_vdso();
	/* Setup the auxv at the stack bottom */
	Elf64_auxv_t *auxv = (Elf64_auxv_t *) buffer;
	unsigned char *scratch_space = (unsigned char *) (auxv + 37);
	for(int i = 0; i < 38; i++)
	{
		if(i != 0)
			auxv[i].a_type = i;
		else
			auxv[i].a_type = 0xffff;
		if(i == 37)
			auxv[i].a_type = 0;
		switch(i)
		{
			case AT_PAGESZ:
				auxv[i].a_un.a_val = PAGE_SIZE;
				break;
			/* We're able to not grab cred because we're inside execve,
			 * there's no race condition */
			case AT_UID:
				auxv[i].a_un.a_val = process->cred.euid;
				break;
			case AT_GID:
				auxv[i].a_un.a_val = process->cred.egid;
				break;
			case AT_RANDOM:
				get_entropy((char*) scratch_space, 16);
				scratch_space += 16;
				break;
			case AT_BASE:
				auxv[i].a_un.a_val = (uintptr_t) process->image_base;
				break;
			case AT_PHENT:
				auxv[i].a_un.a_val = process->info.phent;
				break;
			case AT_PHNUM:
				auxv[i].a_un.a_val = process->info.phnum;
				break;
			case AT_PHDR:
				auxv[i].a_un.a_val = (uintptr_t) process->info.phdr;
				break;
			case AT_EXECFN:
				auxv[i].a_un.a_val = (uintptr_t) scratch_space;
				strcpy((char*) scratch_space, process->cmd_line);
				scratch_space += strlen((const char*) scratch_space) + 1;
				break;
			case AT_SYSINFO_EHDR:
				auxv[i].a_un.a_val = (uintptr_t) process->vdso;
				break;
			case AT_FLAGS:
			{
				/* Lets reuse AT_FLAGS for the purpose of storing dynv */
				/* TODO: Hack? */
				auxv[i].a_un.a_val = (uintptr_t) process->info.dyn;
				break;
			}

			case AT_ENTRY:
			{
				auxv[i].a_un.a_val = (unsigned long) process->info.program_entry;
				break;
			}
		}
	}

	return auxv;
}

void process_kill_other_threads(void);

int flush_old_exec(struct exec_state *state)
{
	if(state->flushed)
		return 0;

	struct process *curr = get_current_process();
	int st = 0;

	process_kill_other_threads();
	
	vm_destroy_addr_space(&curr->address_space);

	memcpy(&curr->address_space, &state->new_address_space, sizeof(struct mm_address_space));

	paging_load_cr3(curr->address_space.cr3);
	
	/* Close O_CLOEXEC files */
	file_do_cloexec(&curr->ctx);

	st = vm_create_brk(&curr->address_space);

	/* And reset the signal disposition */
	signal_do_execve(curr);

	if(st == 0)
	{
		state->flushed = true;
	}

	return st;
}

/*
	return_from_execve(): Return from execve, while loading registers and zero'ing the others.
	Does not return!
*/ 
int return_from_execve(void *entry, int argc, char **argv, char **envp, void *auxv, void *stack);
/*
	execve(2): Executes a program with argv and envp, replacing the current process.
*/

struct inode *pick_between_cwd_and_root(char *p, struct process *proc)
{
	if(*p == '/')
		return get_fs_root();
	else
		return proc->ctx.cwd->f_ino;
}

bool file_is_executable(struct inode *exec_file)
{
	if(exec_file->i_type != VFS_TYPE_FILE || !file_can_access(exec_file, FILE_ACCESS_EXECUTE))
	{
		return false;
	}

	return true;
}
extern size_t used_pages;

int sys_execve(char *p, char *argv[], char *envp[])
{
	int st;
	struct inode *exec_file = NULL;
	struct exec_state state;
	bool exec_state_created = false;
	uint8_t *file = NULL;
	int argc;
	char **kenv = NULL;
	char **karg = NULL;
	struct process *current = get_current_process();

	char *path = strcpy_from_user(p);
	if(!path)
		return -errno;
	
	if((st = exec_state_create(&state)) < 0)
	{
		goto error;
	}

	exec_state_created = true;

	/* Copy argv and envp to the kernel space */
	karg = process_copy_envarg(argv, true, &argc);
	
	if(!karg)
	{
		st = -errno;
		goto error;
	}

	kenv = process_copy_envarg(envp, true, NULL);
	if(!kenv)
	{
		st = -errno;
		goto error;
	}

	/* Open the file */
	struct file *f = get_current_directory();
	exec_file = open_vfs(pick_between_cwd_and_root(path, current), path);

	fd_put(f);

	if(!exec_file)
	{
		st = -errno;
		goto error;
	}

	if(!file_is_executable(exec_file))
	{
		st = -EACCES;
		goto error;
	}

	current->cmd_line = strdup(path);
	if(!current->cmd_line)
	{
		st = -ENOMEM;
		goto error;
	}
	
	/* Setup the binfmt args */
	file = malloc(100);
	if(!file)
	{
		st = -ENOMEM;
		goto error;
	}

	unsigned long old = thread_change_addr_limit(VM_KERNEL_ADDR_LIMIT);

	/* Read the file signature */
	if(read_vfs(0, 0, 100, file, exec_file) < 0)
	{
		st = -errno;
		goto error;
	}

	struct binfmt_args args = {0};
	args.file_signature = file;
	args.filename = current->cmd_line;
	args.argv = karg;
	args.envp = kenv;
	args.file = exec_file;
	args.state = &state;

	/* Load the actual binary */
	void *entry = load_binary(&args);
	if(!entry)
	{
		st = -errno;
		if(state.flushed)
		{
			close_vfs(exec_file);
			free(file);
			goto error_die_signal;
		}
	
		goto error;
	}

	thread_change_addr_limit(old);
	close_vfs(exec_file);

	free(file);

	/* Copy argv and envp to user space memory */
	char **uargv = process_copy_envarg(karg, false, NULL);
	if(!uargv)
	{
		goto error_die_signal;
	}

	free(karg);
	karg = NULL;

	char **uenv = process_copy_envarg(kenv, false, NULL);
	if(!uenv)
	{
		goto error_die_signal;
	}
	
	free(kenv);
	kenv = NULL;

	void *user_stack = get_user_pages(VM_TYPE_SHARED, 256, VM_WRITE | VM_NOEXEC | VM_USER);
	void *auxv = NULL;
	if(!user_stack)
	{
		goto error_die_signal;
	}

	/* Setup auxv */
	auxv = process_setup_auxv(user_stack, current);
	user_stack = (char*) user_stack + 256 * PAGE_SIZE;
	get_current_thread()->user_stack_bottom = user_stack;

	free(path);
	return return_from_execve(entry, argc, uargv, uenv, auxv, user_stack);

error_die_signal:
	free(path);
	free(karg);
	free(kenv);
	kernel_raise_signal(SIGKILL, current, SIGNAL_FORCE, NULL);

	/* This sched_yield should execute the signal handler */
	sched_yield();
	return -1;

error:
	if(exec_state_created) exec_state_destroy(&state);
	free(karg);
	free(kenv);
	free(path);
	free(file);

	if(exec_file)	close_vfs(exec_file);

	return st;
}

int exec_state_create(struct exec_state *state)
{
	int st = 0;
	struct process *current = get_current_process();

	memset(state, 0, sizeof(*state));

	if(vm_clone_as(&state->new_address_space) < 0)
	{
		st = -ENOMEM;
		goto error;
	}

	/* Swap address spaces. Good thing we saved argv and envp before */
	if(vm_create_address_space(&state->new_address_space, current, state->new_address_space.cr3) < 0)
	{
		st = -ENOMEM;
		goto error;
	}

	return st;

error:
	if(state->new_address_space.cr3)
		free_page(phys_to_page((unsigned long) state->new_address_space.cr3));
	return st;
}

void exec_state_destroy(struct exec_state *state)
{
	/* Protect against destructions for flushed exec states */
	if(state->flushed)
		return;
	vm_destroy_addr_space(&state->new_address_space);
}
