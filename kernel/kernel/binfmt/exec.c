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

char **process_copy_envarg(const char **envarg, bool to_kernel, int *count)
{
	/* Copy the envp/argv to another buffer */
	/* Each buffer takes up argc * sizeof pointer + string_size + one extra pointer(to NULL terminate) */
	size_t nr_args = 0;
	size_t string_size = 0;
	const char **b = envarg;
	while(*b)
	{
		size_t length = strlen_user(*b);
		if(length == (size_t) -EFAULT)
			return errno = EFAULT, NULL;

		string_size += length + 1;
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
		panic("old code");
	}

	char *strings = (char*) new + (nr_args + 1) * sizeof(void*);
	char *it = strings;

	/* Actually copy the buffer */
	for(size_t i = 0; i < nr_args; i++)
	{
		size_t length = strlen_user(envarg[i]);
		if(length == (size_t) -EFAULT)
			return errno = EFAULT, NULL;

		if(copy_from_user(it, envarg[i], length) < 0)
			return errno = EFAULT, NULL;

		it += length + 1;
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

size_t count_strings_len(char **ps, int *count)
{
	size_t total_len = 0;
	int _count = 0;

	while(*ps)
	{
		total_len += strlen(*ps++) + 1;
		_count++;
	}

	if(count)
		*count = _count;

	return total_len;
}

/* Sigh... Why doesn't C have references... */
void process_put_strings(char ***pp, char **pstrings, char **vec)
{
	char **p = *pp;
	char *strings = *pstrings;

	while(*vec)
	{
		char *s = strings;
		/* stpcpy returns a pointer to dest, then we add one to account for the null byte */
		//printk("Writing (%s) strlen %lu to %p\n", *vec, strlen(*vec), s);
		strings = stpcpy(strings, *vec) + 1;
		*p = s;
		vec++;
		p++;
	}

	*p++ = NULL;
	*pp = p;
	*pstrings = strings;
}

void *process_setup_auxv(void *buffer, char *strings_space, struct process *process)
{
	process->vdso = vdso_map();
	/* Setup the auxv at the stack bottom */
	Elf64_auxv_t *auxv = (Elf64_auxv_t *) buffer;
	unsigned char *scratch_space = (unsigned char *) strings_space;
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
				auxv[i].a_un.a_val = (uint64_t) scratch_space;
				scratch_space += 16;
				break;
			case AT_BASE:
				auxv[i].a_un.a_val = (uintptr_t) process->interp_base;
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

void process_put_entry_info(struct stack_info *info, char **argv, char **envp)
{
	int envc = 0;
	int argc = 0;
	size_t arg_len = count_strings_len(argv, &argc);
	size_t env_len = count_strings_len(envp, &envc);
	
	/* The calling convention passes argv[0] ... argv[?] = NULL, envp[0] ... envp[?] = NULL, auxv
	 * and only then can we put our strings.
     */
	size_t invariants = sizeof(long) + ((argc + 1) * sizeof(void *)) + ((envc + 1) * sizeof(void *))
	                    + 38 * sizeof(Elf64_auxv_t);

	size_t total_info_len = arg_len + env_len + invariants
	       + strlen(get_current_process()->cmd_line) + 1 + 16;
	//printk("Old top: %p\n", info->top);
	info->top = (void *) ((unsigned long) info->top - total_info_len);

	__attribute__((may_alias)) char **pointers_base = info->top;
	__attribute__((may_alias)) char *strings_space = (char *) pointers_base + invariants;

	__attribute__((may_alias)) long *pargc = (long *) pointers_base;
	*pargc = argc;
	//printk("argv at %p\n", pointers_base);
	pointers_base = (void *)((char *) pointers_base + sizeof(long));
	process_put_strings(&pointers_base, &strings_space, argv);
	//printk("envp at %p\n", pointers_base);
	process_put_strings(&pointers_base, &strings_space, envp);
	//printk("auxv at %p\n", pointers_base);
	process_setup_auxv(pointers_base, strings_space, get_current_process());
	//printk("Stack pointer: %p\n", info->top);
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
	mutex_init(&curr->address_space.vm_lock);

	vm_load_arch_mmu(&curr->address_space.arch_mmu);
	
	/* Close O_CLOEXEC files */
	file_do_cloexec(&curr->ctx);

	st = vm_create_brk(&curr->address_space);

	if(st == 0)
	{
		state->flushed = true;
	}

	/* And reset the signal disposition */
	signal_do_execve(curr);

	return st;
}

/*
	return_from_execve(): Return from execve, while loading registers and zero'ing the others.
	Does not return!
*/ 
int return_from_execve(void *entry, void *stack);
/*
	execve(2): Executes a program with argv and envp, replacing the current process.
*/

struct file *pick_between_cwd_and_root(char *p, struct process *proc)
{
	if(*p == '/')
		return get_fs_root();
	else
		return proc->ctx.cwd;
}

bool file_is_executable(struct file *exec_file)
{
	if(exec_file->f_ino->i_type != VFS_TYPE_FILE || !file_can_access(exec_file, FILE_ACCESS_EXECUTE))
	{
		return false;
	}

	return true;
}
extern size_t used_pages;

int sys_execve(const char *p, const char *argv[], const char *envp[])
{
	int st;
	struct file *exec_file = NULL;
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

	/* We might be getting called from kernel code, so force the address limit */
	thread_change_addr_limit(VM_USER_ADDR_LIMIT);

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
	file = zalloc(BINFMT_SIGNATURE_LENGTH);
	if(!file)
	{
		st = -ENOMEM;
		goto error;
	}

	unsigned long old = thread_change_addr_limit(VM_KERNEL_ADDR_LIMIT);

	/* Read the file signature */
	if(read_vfs(0, BINFMT_SIGNATURE_LENGTH, file, exec_file) < 0)
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
	args.argc = &argc;

	/* Load the actual binary */
	void *entry = load_binary(&args);

	/* Update the pointers since the binary loader might've changed them(for example, shebang does that) */
	karg = args.argv;
	kenv = args.envp;

	if(!entry)
	{
		st = -errno;
		if(state.flushed)
		{
			fd_put(exec_file);
			free(file);
			goto error_die_signal;
		}
	
		goto error;
	}

	thread_change_addr_limit(old);
	fd_put(exec_file);

	free(file);

	current->flags &= ~PROCESS_FORKED;

	struct stack_info si;
	si.length = DEFAULT_USER_STACK_LEN;
	
	if(process_alloc_stack(&si) < 0)
		goto error_die_signal;

	process_put_entry_info(&si, karg, kenv);
	free(karg);
	free(kenv);
	free(path);

	context_tracking_exit_kernel();
	return return_from_execve(entry, si.top);

error_die_signal:
	free(path);
	free(karg);
	free(kenv);
	kernel_raise_signal(SIGKILL, current, SIGNAL_FORCE, NULL);

	/* This return should execute the signal handler */
	return -1;

error: ;
	if(exec_state_created) exec_state_destroy(&state);
	free(karg);
	free(kenv);
	free(path);
	free(file);

	if(exec_file)	fd_put(exec_file);

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
		goto error0;
	}

	/* Swap address spaces. Good thing we saved argv and envp before */
	if(vm_create_address_space(&state->new_address_space, current) < 0)
	{
		st = -ENOMEM;
		goto error;
	}

	return st;

error:
	vm_free_arch_mmu(&state->new_address_space.arch_mmu);
error0:
	return st;
}

void exec_state_destroy(struct exec_state *state)
{
	/* Protect against destructions for flushed exec states */
	if(state->flushed)
		return;
	vm_destroy_addr_space(&state->new_address_space);
}
