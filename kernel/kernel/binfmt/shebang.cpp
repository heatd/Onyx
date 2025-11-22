/*
 * Copyright (c) 2020 - 2025 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <errno.h>
#include <stdio.h>
#include <string.h>

#include <onyx/binfmt.h>
#include <onyx/process.h>

static char *find_space_or_tab(const char *str, size_t len)
{
    while (len--)
    {
        if (*str == ' ' || *str == '\t')
            return (char *) str;
        str++;
    }

    return nullptr;
}

static char *find_space_or_tab_or_zero(const char *str, size_t len)
{
    while (len--)
    {
        if (*str == ' ' || *str == '\t' || *str == '\0')
            return (char *) str;
        str++;
    }

    return nullptr;
}

static char *find_not_space_nor_tab(const char *str, size_t len)
{
    while (len--)
    {
        if (*str != ' ' && *str != '\t')
            return (char *) str;
        str++;
    }

    return nullptr;
}

void *shebang_load(struct binfmt_args *args)
{
    char *buf = (char *) args->file_signature;
    char *end = buf + BINFMT_SIGNATURE_LENGTH;

    if (args->is_interp)
    {
        /* Tried to load a shebang file as an interpreter? This is not going to work. Stop now
         * instead of recursing further. */
        pr_warn_once(
            "exec: %s[%d]: Tried to load a shebang executable as an interpreter, failing\n",
            get_current_process()->comm, get_current_process()->pid_);
        return errno = ENOEXEC, nullptr;
    }

    char *p = strnchr(buf, BINFMT_SIGNATURE_LENGTH, '\n');
    if (!p)
    {
        /* If we don't have a newline in the buffer, check for a space or tab.
         * If we can find it, the interpreter path isn't truncated, so we can continue.
         */
        p = find_not_space_nor_tab(buf + 2, BINFMT_SIGNATURE_LENGTH - 2);

        /* The entire buffer is spaces/tabs, so it's a bad executable */
        if (!p)
            return errno = ENOEXEC, nullptr;

        /* Interpreter path truncated. */
        if (!find_space_or_tab_or_zero(p, end - p))
            return errno = ENOEXEC, nullptr;
        p = end - 1;
    }

    /* Now we need to null terminate the buffer and overwrite spaces/tabs at the end with zeroes */
    *p = '\0';
    p--;

    while (p > buf)
    {
        if (*p == ' ' || *p == '\t')
            *p = '\0';
        else
            break;
        p--;
    }

    /* Point to buf + 2(the length of #!) and go past the initial spaces/tabs */
    char *interp = buf + 2;

    while (*interp == ' ' || *interp == '\t')
        interp++;

    /* There's no path :( */
    if (*interp == '\0')
        return errno = ENOEXEC, nullptr;

    char *arg = find_space_or_tab_or_zero(interp, end - interp);
    if (*arg != '\0')
    {
        while (*arg == ' ' || *arg == '\t')
            *arg++ = '\0';
    }
    else
        arg = nullptr;

    interp = strdup(interp);
    if (!interp)
        return errno = ENOMEM, nullptr;

    char **old_kargs = args->argv;

    bool argc_is_zero = *args->argc == 0;

    /* Calculate the new argc */
    int argc = *args->argc + (arg != nullptr ? 2 : 1);

    if (argc_is_zero)
        argc++;

    char **new_argv = (char **) calloc(argc + 1, sizeof(void *));
    if (!new_argv)
    {
        free(interp);
        return errno = ENOMEM, nullptr;
    }

    int curr = 0;
    new_argv[curr++] = interp;
    if (arg)
        new_argv[curr++] = arg;

    /* We take the time to insert an argv[0] with the script's name forcefully. */
    if (argc_is_zero)
        new_argv[curr++] = args->filename;

    for (int i = 0; i < *args->argc + 1; i++)
    {
        char *a = old_kargs[i];
        if (i == 0)
            a = args->filename;

        new_argv[curr++] = a;
    }

    unsigned long limit = thread_change_addr_limit(VM_KERNEL_ADDR_LIMIT);

    auto ex = process_copy_envarg((const char **) new_argv, args->envp_size);

    thread_change_addr_limit(limit);

    free(new_argv);

    if (ex.has_error())
    {
        free(interp);
        return errno = -ex.error(), nullptr;
    }

    auto res = ex.value();

    args->argv = res.s;
    *args->argc = res.count;
    args->argv_size = res.total_size;

    free(old_kargs);

    args->interp_path = interp;

    void *entry = bin_do_interp(args);

    free(interp);
    args->interp_path = nullptr;

    return entry;
}

bool shebang_is_valid(uint8_t *signature)
{
    return memcmp(signature, "#!", 2) == 0;
}

struct binfmt shebang_binfmt = {.signature = (unsigned char *) "#!",
                                .size_signature = 2,
                                .is_valid_exec = shebang_is_valid,
                                .callback = shebang_load,
                                .next = nullptr};

__init static void __shebang_init()
{
    install_binfmt(&shebang_binfmt);
}
