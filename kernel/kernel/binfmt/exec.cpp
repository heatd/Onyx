/*
 * Copyright (c) 2020 - 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#include <errno.h>
#include <stdio.h>
#include <string.h>

#include <onyx/binfmt.h>
#include <onyx/exec.h>
#include <onyx/file.h>
#include <onyx/kunit.h>
#include <onyx/process.h>
#include <onyx/random.h>
#include <onyx/signal.h>
#include <onyx/user.h>
#include <onyx/vdso.h>

void exec_state_destroy(struct exec_state *state);

expected<envarg_res, int> process_copy_envarg(const char **envarg, size_t current_size)
{
    /* Copy the envp/argv to another buffer
     * Each buffer takes up argc * sizeof pointer + string_size + one extra pointer
     * (to nullptr terminate)
     */
    size_t nr_args = 0;
    size_t string_size = 0;
    const char **b = envarg;
    const char *ptr = nullptr;
    long st;

    while ((st = get_user64((unsigned long *) b, (unsigned long *) &ptr)) == 0 && ptr != nullptr)
    {
        ssize_t length = strlen_user(ptr);
        if (length == -EFAULT)
            return unexpected<int>{-EFAULT};

        string_size += length + 1;
        nr_args++;

        if (nr_args > INT_MAX)
            return unexpected<int>{-E2BIG};

        b++;
    }

    if (st < 0)
        return unexpected<int>{-EFAULT};

    size_t buffer_size = (nr_args + 1) * sizeof(void *) + string_size;

    // Check if we overflow the ARG_MAX
    if (current_size + buffer_size > ARG_MAX)
        return unexpected<int>{-E2BIG};

    char *new_ = (char *) zalloc(buffer_size);
    if (!new_)
        return unexpected<int>{-ENOMEM};

    char *strings = (char *) new_ + (nr_args + 1) * sizeof(void *);
    char *it = strings;

    /* Actually copy the buffer */
    for (size_t i = 0; i < nr_args; i++)
    {
        const char *str;
        if (get_user64((unsigned long *) &envarg[i], (unsigned long *) &str) < 0)
            return unexpected<int>{-EFAULT};

        ssize_t length = strlen_user(str);
        if (length == -EFAULT)
            return unexpected<int>{-EFAULT};

        if (copy_from_user(it, str, length) < 0)
            return unexpected<int>{-EFAULT};

        it += length + 1;
    }

    char **new_args = (char **) new_;
    for (size_t i = 0; i < nr_args; i++)
    {
        new_args[i] = (char *) strings;
        strings += strlen(new_args[i]) + 1;
    }

    struct envarg_res r;
    r.s = new_args;
    r.count = nr_args;
    r.total_size = buffer_size;

    return r;
}

size_t count_strings_len(char **ps, int *count)
{
    size_t total_len = 0;
    int _count = 0;

    while (*ps)
    {
        total_len += strlen(*ps++) + 1;
        _count++;
    }

    if (count)
        *count = _count;

    return total_len;
}

static char *copy_string(char *s1, const char *s2)
{
    char *dst = s1;
    const char *src = s2;
    size_t src_len = strlen(src);

    if (copy_to_user(dst, src, src_len) < 0)
        return nullptr;

    return dst + src_len;
}

/* Sigh... Why doesn't C have references... */
int process_put_strings(char ***pp, char **pstrings, char **vec)
{
    char **p = *pp;
    char *strings = *pstrings;
    char *nullptr_ptr = nullptr;

    while (*vec)
    {
        char *s = strings;
        /* stpcpy returns a pointer to dest, then we add one to account for the nullptr byte */
        // printk("Writing (%s) strlen %lu to %p\n", *vec, strlen(*vec), s);
        strings = copy_string(strings, *vec) + 1;
        if (!strings)
            return -EFAULT;

        if (copy_to_user(p, &s, sizeof(char *)) < 0)
            return -EFAULT;

        vec++;
        p++;
    }

    if (copy_to_user(p, &nullptr_ptr, sizeof(char *)) < 0)
        return -EFAULT;

    *pp = ++p;
    *pstrings = strings;

    return 0;
}

/* TODO: Hacky, we should implement this in optimised assembly! */
static int put_user32(uint32_t *uptr, uint32_t val)
{
    return copy_to_user(uptr, &val, sizeof(uint32_t));
}

static int put_user64(uint64_t *uptr, uint64_t val)
{
    return copy_to_user(uptr, &val, sizeof(uint64_t));
}

void *process_setup_auxv(void *buffer, char *strings_space, struct process *process)
{
    process->vdso = vdso_map();
    /* Setup the auxv at the stack bottom */
    Elf64_auxv_t *auxv = (Elf64_auxv_t *) buffer;
    unsigned char *scratch_space = (unsigned char *) strings_space;
    for (int i = 0; i < 38; i++)
    {
        uint64_t type;
        uint64_t val = 0;

        if (i != 0)
            type = i;
        else
            type = 0xffff;
        if (i == 37)
            type = 0;

        switch (i)
        {
            case AT_SECURE:
                val = (bool) (process->flags & PROCESS_SECURE);
                break;
            case AT_PAGESZ:
                val = PAGE_SIZE;
                break;
            /* We're able to not grab cred because we're inside execve,
             * there's no race condition */
            case AT_UID:
                val = process->cred.ruid;
                break;
            case AT_GID:
                val = process->cred.rgid;
                break;
            case AT_EUID:
                val = process->cred.euid;
                break;
            case AT_EGID:
                val = process->cred.egid;
                break;
            case AT_RANDOM:;
                {
                    char s[16];
                    get_entropy((char *) s, 16);

                    if (copy_to_user(scratch_space, s, 16) < 0)
                        return nullptr;

                    val = (uint64_t) scratch_space;
                    scratch_space += 16;
                }
                break;
            case AT_BASE:
                val = (uintptr_t) process->interp_base;
                break;
            case AT_PHENT:
                val = process->info.phent;
                break;
            case AT_PHNUM:
                val = process->info.phnum;
                break;
            case AT_PHDR:
                val = process->info.phdr;
                break;
            case AT_EXECFN:

            {
                val = (uintptr_t) scratch_space;
                // This should be safe since we're the only thread running, no race conditions I
                // would say.
                // TODO: Unless we ever add a way to set it from another process?
                size_t len = process->cmd_line.length() + 1;
                if (copy_to_user((char *) scratch_space, process->cmd_line.c_str(), len) < 0)
                    return nullptr;

                scratch_space += len;
            }
            break;
            case AT_SYSINFO_EHDR:
                val = (uintptr_t) process->vdso;
                break;
            case AT_FLAGS: {
                break;
            }

            case AT_ENTRY: {
                val = (unsigned long) process->info.program_entry;
                break;
            }
        }

        if (put_user64(&auxv[i].a_type, type) < 0)
            return nullptr;

        if (put_user64(&auxv[i].a_un.a_val, val) < 0)
            return nullptr;
    }

    return auxv;
}

int process_put_entry_info(struct stack_info *info, char **argv, char **envp)
{
    int envc = 0;
    int argc = 0;
    size_t arg_len = count_strings_len(argv, &argc);
    size_t env_len = count_strings_len(envp, &envc);

    /* The calling convention passes argv[0] ... argv[?] = nullptr, envp[0] ... envp[?] = nullptr,
     * auxv and only then can we put our strings.
     */
    size_t invariants = sizeof(long) + ((argc + 1) * sizeof(void *)) +
                        ((envc + 1) * sizeof(void *)) + 38 * sizeof(Elf64_auxv_t);

    size_t total_info_len = ALIGN_TO(
        arg_len + env_len + invariants + get_current_process()->cmd_line.length() + 1 + 16, 16);
    // printk("Old top: %p\n", info->top);
    info->top = (void *) ((unsigned long) info->top - total_info_len);

    __attribute__((may_alias)) char **pointers_base = (char **) info->top;
    __attribute__((may_alias)) char *strings_space = (char *) pointers_base + invariants;

    __attribute__((may_alias)) long *pargc = (long *) pointers_base;
    if (copy_to_user(pargc, &argc, sizeof(argc)) < 0)
        return -EFAULT;

    // printk("argv at %p\n", pointers_base);
    pointers_base = (char **) ((char *) pointers_base + sizeof(long));
    if (process_put_strings(&pointers_base, &strings_space, argv) < 0)
        return -EFAULT;

    // printk("envp at %p\n", pointers_base);
    if (process_put_strings(&pointers_base, &strings_space, envp) < 0)
        return -EFAULT;
    // printk("auxv at %p\n", pointers_base);
    if (!process_setup_auxv(pointers_base, strings_space, get_current_process()))
        return -EFAULT;
    // printk("Stack pointer: %p\n", info->top);

    return 0;
}

void process_kill_other_threads(void);

int flush_old_exec(struct exec_state *state)
{
    if (state->flushed)
        return 0;

    struct process *curr = get_current_process();
    int st = 0;

    process_kill_other_threads();

    vm_set_aspace(state->new_address_space.get());

    curr->address_space = cul::move(state->new_address_space);
    mutex_init(&curr->address_space->vm_lock);

    /* Close O_CLOEXEC files */
    file_do_cloexec(&curr->ctx);

    st = vm_create_brk(curr->address_space.get());

    if (st == 0)
    {
        state->flushed = true;
    }

    curr->interp_base = nullptr;
    curr->image_base = nullptr;

    /* And reset the signal disposition */
    signal_do_execve(curr);

    return st;
}

/*
    return_from_execve(): Return from execve, while loading registers and zero'ing the others.
    Does not return!
*/
extern "C" [[noreturn]] void return_from_execve(void *entry, void *stack);
/*
    execve(2): Executes a program with argv and envp, replacing the current process.
*/

struct file *pick_between_cwd_and_root(char *p, struct process *proc)
{
    if (*p == '/')
        return get_fs_root();
    else
        return proc->ctx.cwd;
}

bool file_is_executable(struct file *exec_file)
{
    if (exec_file->f_ino->i_type != VFS_TYPE_FILE ||
        !file_can_access(exec_file, FILE_ACCESS_EXECUTE))
    {
        return false;
    }

    return true;
}

int sys_execve(const char *p, const char **argv, const char **envp)
{
    int st;
    struct file *exec_file = nullptr;
    struct exec_state state;
    bool exec_state_created = false;
    uint8_t *file = nullptr;
    int argc;
    char **kenv = nullptr;
    char **karg = nullptr;
    struct file *f = nullptr;
    unsigned long old = 0;
    void *entry = nullptr;
    binfmt_args args{};
    envarg_res er;
    expected<envarg_res, int> ex;
    struct process *current = get_current_process();

    char *path = strcpy_from_user(p);
    if (!path)
        return -errno;

    if ((st = exec_state_create(&state)) < 0)
    {
        goto error;
    }

    exec_state_created = true;

    /* Copy argv and envp to the kernel space */
    if (ex = process_copy_envarg(argv, 0); ex.has_error())
    {
        st = ex.error();
        goto error;
    }

    er = ex.value();

    args.argv_size = er.total_size;
    argc = er.count;
    karg = er.s;

    if (ex = process_copy_envarg(envp, args.argv_size); ex.has_error())
    {
        st = ex.error();
        goto error;
    }

    er = ex.value();

    args.envp_size = er.total_size;
    kenv = er.s;

    /* We might be getting called from kernel code, so force the address limit */
    thread_change_addr_limit(VM_USER_ADDR_LIMIT);

    /* Open the file */
    f = get_current_directory();
    exec_file = open_vfs(pick_between_cwd_and_root(path, current), path);

    fd_put(f);

    if (!exec_file)
    {
        st = -errno;
        goto error;
    }

    if (!file_is_executable(exec_file))
    {
        st = -EACCES;
        goto error;
    }

    /* Setup the binfmt args */
    file = (uint8_t *) zalloc(BINFMT_SIGNATURE_LENGTH);
    if (!file)
    {
        st = -ENOMEM;
        goto error;
    }

    old = thread_change_addr_limit(VM_KERNEL_ADDR_LIMIT);

    /* Read the file signature */
    if (read_vfs(0, BINFMT_SIGNATURE_LENGTH, file, exec_file) < 0)
    {
        st = -errno;
        goto error;
    }

    args.file_signature = file;
    args.filename = path;
    args.argv = karg;
    args.envp = kenv;
    args.file = exec_file;
    args.state = &state;
    args.argc = &argc;

    /* Load the actual binary */
    entry = load_binary(&args);

    /* Update the pointers since the binary loader might've changed them(for example, shebang does
     * that) */
    karg = args.argv;
    kenv = args.envp;

    if (state.flushed)
    {
        // Wake up waiters stuck on vfork
        if (current->vfork_compl)
        {
            current->vfork_compl->wake();
            current->vfork_compl = nullptr;
        }
    }

    if (!entry)
    {
        st = -errno;
        if (state.flushed)
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

    if (!current->set_cmdline(std::string_view(path)))
        goto error_die_signal;

    current->flags &= ~PROCESS_FORKED;

    struct stack_info si;
    si.length = DEFAULT_USER_STACK_LEN;

    if (process_alloc_stack(&si) < 0)
        goto error_die_signal;

    if (process_put_entry_info(&si, karg, kenv) < 0)
        goto error_die_signal;

    free(karg);
    free(kenv);
    free(path);

    context_tracking_exit_kernel();
    return_from_execve(entry, si.top);

error_die_signal:
    free(path);
    free(karg);
    free(kenv);
    kernel_raise_signal(SIGKILL, current, SIGNAL_FORCE, nullptr);

    /* This return should execute the signal handler */
    return -1;

error:;
    if (exec_state_created)
        exec_state_destroy(&state);
    free(karg);
    free(kenv);
    free(path);
    free(file);

    if (exec_file)
        fd_put(exec_file);

    return st;
}

int exec_state_create(struct exec_state *state)
{
    auto ex = mm_address_space::create();
    if (ex.has_error())
        return ex.error();

    state->new_address_space = ex.value();

    /* Swap address spaces. Good thing we saved argv and envp before */
    if (vm_create_address_space(state->new_address_space.get()) < 0)
    {
        return -ENOMEM;
    }

    return 0;
}

void exec_state_destroy(struct exec_state *state)
{
    /* Protect against destructions for flushed exec states */
    if (state->flushed)
        return;
}

#ifdef CONFIG_KUNIT

TEST(exec, arg_max_handling)
{
    auto_addr_limit l_{VM_KERNEL_ADDR_LIMIT};
    // Test that the accounting is accurate
    const char *args[] = {"hello", nullptr};

    auto ex = process_copy_envarg(args, 0);

    ASSERT_TRUE(ex.has_value());

    auto res = ex.value();

    ASSERT_NONNULL(res.s);
    ASSERT_EQ(res.count, 1);
    ASSERT_EQ(res.total_size, (2 * sizeof(const char *) + (strlen("hello") + 1)));

    free(res.s);

    // Test that arguments too large result in E2BIG
    size_t number_args = (ARG_MAX / PAGE_SIZE) + 2;

    cul::vector<char *> v;

    for (size_t i = 0; i < number_args; i++)
    {
        char *s = (char *) malloc(PAGE_SIZE);
        ASSERT_NONNULL(s);
        memset(s, 'A', PAGE_SIZE);
        s[PAGE_SIZE - 1] = '\0';
        ASSERT_TRUE(v.push_back(s));
    }

    ASSERT_TRUE(v.push_back(nullptr));

    ex = process_copy_envarg((const char **) v.begin(), 0);

    for (auto &s : v)
        free(s);

    ASSERT_TRUE(ex.has_error());
    ASSERT_TRUE(ex.error() == -E2BIG);
}
#endif
