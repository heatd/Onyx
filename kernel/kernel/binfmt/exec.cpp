/*
 * Copyright (c) 2020 - 2025 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#define DEFINE_CURRENT
#include <errno.h>
#include <stdio.h>
#include <string.h>

#include <onyx/binfmt.h>
#include <onyx/err.h>
#include <onyx/exec.h>
#include <onyx/file.h>
#include <onyx/kunit.h>
#include <onyx/mm/slab.h>
#include <onyx/namei.h>
#include <onyx/process.h>
#include <onyx/random.h>
#include <onyx/signal.h>
#include <onyx/user.h>
#include <onyx/vdso.h>
#include <onyx/vector.h>
#include <onyx/vfork_completion.h>

#include <platform/elf.h>

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
    /* TODO: Take into account rlim_stack */
    unsigned long limit = (8 * DEFAULT_USER_STACK_LEN) / 4;
    limit = cul::max(limit, (unsigned long) ARG_MAX);

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
    if (current_size + buffer_size > limit)
        return unexpected<int>{-E2BIG};

    char *new_ = (char *) kcalloc(buffer_size, 1, GFP_KERNEL);
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
    struct mm_address_space *mm = process->address_space;
    void *user_auxv = (void *) buffer;
    unsigned char *scratch_space = (unsigned char *) strings_space;
    u8 *execfn;
    unsigned int i = 0;
    char s[16];
    u8 *random;
    process->vdso = vdso_map();
    /* Setup the auxv at the stack bottom */

#define PUT_AUXV(type, val)         \
    ({                              \
        mm->saved_auxv[i++] = type; \
        mm->saved_auxv[i++] = val;  \
    })

    random = scratch_space;
    get_entropy((char *) s, 16);

    if (copy_to_user(random, s, 16) < 0)
        return nullptr;
    scratch_space += 16;

    execfn = scratch_space;
    size_t len = process->cmd_line.length() + 1;
    // This should be safe since we're the only thread running, no race conditions I
    // would say.
    // TODO: Unless we ever add a way to set it from another process?
    if (copy_to_user((char *) execfn, process->cmd_line.c_str(), len) < 0)
        return nullptr;
    scratch_space += len;

    PUT_AUXV(AT_SECURE, (bool) (process->flags & PROCESS_SECURE));
    PUT_AUXV(AT_PAGESZ, PAGE_SIZE);
    PUT_AUXV(AT_UID, process->cred.ruid);
    PUT_AUXV(AT_GID, process->cred.rgid);
    PUT_AUXV(AT_EUID, process->cred.ruid);
    PUT_AUXV(AT_EGID, process->cred.rgid);
    PUT_AUXV(AT_RANDOM, (unsigned long) random);
    PUT_AUXV(AT_BASE, (unsigned long) process->interp_base);
    PUT_AUXV(AT_PHENT, process->info.phent);
    PUT_AUXV(AT_PHNUM, process->info.phnum);
    PUT_AUXV(AT_PHDR, process->info.phdr);
    PUT_AUXV(AT_EXECFN, (unsigned long) execfn);
    PUT_AUXV(AT_SYSINFO_EHDR, (unsigned long) process->vdso);
    PUT_AUXV(AT_FLAGS, 0);
    PUT_AUXV(AT_ENTRY, (unsigned long) process->info.program_entry);
    PUT_AUXV(AT_CLKTCK, 1000);
#ifdef ELF_HWCAP
    PUT_AUXV(AT_HWCAP, ELF_HWCAP);
#endif
    PUT_AUXV(AT_NULL, 0);

    if (copy_to_user(user_auxv, mm->saved_auxv, i * sizeof(unsigned long)) < 0)
        return nullptr;
    return user_auxv;
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
    current->address_space->arg_start = (unsigned long) strings_space;
    if (process_put_strings(&pointers_base, &strings_space, argv) < 0)
        return -EFAULT;
    current->address_space->arg_end = (unsigned long) strings_space;

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
    struct mm_address_space *mm = curr->address_space;
    int st = 0;

    st = zap_threads_exec();
    if (st < 0)
        return st;

    vm_set_aspace(state->new_address_space);
    curr->address_space = cul::move(state->new_address_space);
    if (mm != &kernel_address_space)
        mmput(mm);

    // Wake up waiters stuck on vfork
    if (current->vfork_compl)
    {
        vfork_compl_wake(current->vfork_compl);
        current->vfork_compl = nullptr;
    }

    rwlock_init(&curr->address_space->vm_lock);

    /* Close O_CLOEXEC files */
    file_do_cloexec(curr->ctx);

    st = vm_create_brk(curr->address_space);
    if (st == 0)
        state->flushed = true;

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

bool file_is_executable(struct file *exec_file)
{
    if (!S_ISREG(exec_file->f_ino->i_mode) || !file_can_access(exec_file, FILE_ACCESS_EXECUTE))
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
    unsigned long old = 0;
    void *entry = nullptr;
    binfmt_args args{};
    envarg_res er;
    expected<envarg_res, int> ex;

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
    if (auto ex = vfs_open(AT_FDCWD, path, O_RDONLY, 0); ex.has_error())
    {
        st = ex.error();
        goto error;
    }
    else
        exec_file = ex.value();

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
    if (st = read_vfs(0, BINFMT_SIGNATURE_LENGTH, file, exec_file); st < 0)
        goto error;

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
    si.length = PAGE_SIZE;

    if (process_alloc_stack(&si) < 0)
        goto error_die_signal;

    current->address_space->stack_start = (unsigned long) si.base;
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
    auto ex = mm_create();
    if (IS_ERR(ex))
        return PTR_ERR(ex);

    state->new_address_space = ex;
    /* Swap address spaces. Good thing we saved argv and envp before */
    if (vm_create_address_space(state->new_address_space) < 0)
        return -ENOMEM;

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
