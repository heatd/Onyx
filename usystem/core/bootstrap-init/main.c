/*
 * Copyright (c) 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

int mount_autodetect(const char *dev, const char *mpoint)
{
    const char *fs_type[] = {"ext2"};

    for (int i = 0; i < 1; i++)
    {
        if (mount(dev, mpoint, fs_type[i], 0, NULL) == 0)
            return 0;
    }

    return -1;
}

int option_verbose = 0;

const struct option options[] = {
    {"root", required_argument, NULL, 'r'}, {"verbose", no_argument, &option_verbose, 1}, {}};

int insmod(const char *path, const char *name)
{
    return syscall(SYS_insmod, path, name);
}

#define MODULE_PREFIX "/usr/lib/modules/"
#define MODULE_EXT    ".ko"

int load_modules(void)
{
    int st = 0;
    /* Open the modules file */
    FILE *file = fopen("/etc/modules.load", "re");
    if (!file)
    {
        // Ok, doesn't exist. No problem.
        return 0;
    }

    char *buf = NULL;
    size_t buflen = 0;
    ssize_t l = 0;
    /* At every line there's a module name. Get it, and insmod it */
    while ((l = getline(&buf, &buflen, file)) != -1)
    {
        if (buf[l - 1] == '\n')
            buf[l - 1] = '\0';

        if (buf[0] == '\0')
            continue;

        char *path = malloc(strlen(MODULE_PREFIX) + strlen(buf) + strlen(MODULE_EXT) + 1);
        if (!path)
        {
            st = -1;
            goto out;
        }

        strcpy(path, MODULE_PREFIX);
        strcat(path, buf);
        strcat(path, MODULE_EXT);

        if (option_verbose)
            fprintf(stderr, "bootstrap-init: loading module %s (path %s)\n", buf, path);

        st = insmod(path, buf);
        if (st < 0)
        {
            perror("insmod");
            free(path);
            goto out;
        }

        free(path);
    }

    if (!feof(file))
    {
        perror("error reading module file");
        st = -1;
        goto out;
    }
out:
    free(buf);
    fclose(file);
    return st;
}

static void drop_to_rescue_sh()
{
    fprintf(stderr, "bootstrap-init: dropping into rescue shell\n");
    if (chdir("/") < 0)
    {
        perror("chdir(\"/");
        return;
    }

    setsid();
    ioctl(0, TIOCSCTTY, (void *) 1);
    if (tcsetpgrp(0, getpid()) < 0)
        perror("tcsetpgrp");

    if (execl("/bin/dash", "-/bin/dash", NULL) < 0)
        perror("exec");
}

static int do_fsck(const char *bdev)
{
    /* No support for anything else right now */
    const char *filesystems[] = {"ext2", "ext3", "ext4"};
    char buf[64];
    int exec = 0;
    int wstatus;
    pid_t pid;

    for (unsigned int i = 0; i < sizeof(filesystems) / sizeof(filesystems[0]); i++)
    {
        sprintf(buf, "/sbin/fsck.%s", filesystems[i]);
        if (access(buf, X_OK) == 0)
        {
            /* Ok, it's here, let's exec */
            pid = fork();
            if (pid == 0)
            {
                /* -p = no questions */
                if (execl(buf, buf, "-p", bdev, NULL) < 0)
                {
                    perror("exec");
                    exit(1);
                }
            }
            else if (pid < 0)
            {
                perror("fork");
                return -1;
            }

            exec = 1;
            break;
        }
    }

    if (!exec)
    {
        printf("fsck not found, continuing\n");
        return 0;
    }

    if (wait(&wstatus) < 0)
    {
        perror("wait");
        return 1;
    }

    if (!WIFEXITED(wstatus))
    {
        if (WIFSIGNALED(wstatus))
            printf("%s exited with signal %d\n", buf, WTERMSIG(wstatus));
        return -1;
    }

    /* Now we get to interpret the exit code. We can tolerate 0 or 1 - anything else should drop to
     * a rescue shell (0 = clean, 1 = corrected) */
    if (WEXITSTATUS(wstatus) == 0 || WEXITSTATUS(wstatus) == 1)
        return 0;
    printf("%s exited with error code %d\n", buf, WEXITSTATUS(wstatus));
    return -1;
}

int main(int argc, char **argv)
{
    // Ok so our job is to load initial modules and mount root
    // If we fail, try to execute /bin/dash as a rescue shell.

    /* Check if we're actually the first process */
    pid_t p = getpid();
    if (p != 1)
    {
        fprintf(stderr, "bootstrap-init: error: Invoked after system boot.\n");
        return 1;
    }

    // First, (try to) create /dev if it doesn't exist
    if (mkdir("/dev", 0755) == -1 && errno != EEXIST)
    {
        return 1;
    }

    // Mount devfs
    if (mount("none", "/dev", "devfs", 0, NULL) < 0)
        return 2;

    // Open fd 0, 1, 2
    int flags[] = {O_RDONLY, O_WRONLY, O_WRONLY};

    for (int i = 0; i < 3; i++)
    {
        int fd = open("/dev/console", flags[i] | O_NOCTTY);

        if (fd < 0)
            return 3;

        dup2(fd, i);

        if (fd != i)
            close(fd);
    }

    const char *root_blockdev = NULL;

    // We have output now.
    // Try to mount the root filesystem, but first, parse arguments.
    // Note that we ignore all options that we don't recognize (they're not meant for us)

    int optindex = 0;
    int opt;
    while ((opt = getopt_long_only(argc, argv, "r:", options, &optindex)) != -1)
    {
        switch (opt)
        {
            case 'r':
                root_blockdev = strdup(optarg);
                if (!root_blockdev)
                {
                    perror("strdup");
                    return 1;
                }

                break;
        }
    }

    if (!root_blockdev)
    {
        fprintf(stderr, "bootstrap-init: Error: root block device not specified!\n");
        return 1;
    }

    if (option_verbose)
        fprintf(stderr, "bootstrap-init: Loading modules...\n");

    int st = load_modules();

    if (st < 0)
    {
        fprintf(stderr, "bootstrap-init: Module loading failed, exiting...\n");
        return 1;
    }

    if (option_verbose)
        fprintf(stderr, "bootstrap-init: Mounting root filesystem %s...\n", root_blockdev);

    /* fsck the root block device */
    st = do_fsck(root_blockdev);
    if (st)
    {
        drop_to_rescue_sh();
        return 1;
    }

    st = mount_autodetect(root_blockdev, "/");

    free((void *) root_blockdev);

    if (st < 0)
    {
        perror("Error mounting root");
        drop_to_rescue_sh();
        return 1;
    }

    if (option_verbose)
        fprintf(stderr, "bootstrap-init: root mounted, remounting dev\n");

    if (mount("none", "/dev", "devfs", 0, NULL) < 0)
        return 2;

    if (option_verbose)
        fprintf(stderr, "bootstrap-init: root mounting done, exec'ing the new init\n");

    if (execve("/sbin/init", argv, environ) < 0)
    {
        perror("Failed to execute /sbin/init");
        drop_to_rescue_sh();
        return 1;
    }
}
