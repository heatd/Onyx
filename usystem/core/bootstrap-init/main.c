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

const struct option options[] = {{"root", required_argument, NULL, 'r'},
                                 {"verbose", no_argument, &option_verbose, 1}};

int insmod(const char *path, const char *name)
{
    return syscall(SYS_insmod, path, name);
}

int fmount(int fd, char *path)
{
    if (syscall(SYS_fmount, fd, path))
        return -1;
    return 0;
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

    if (tcsetpgrp(0, getpid()) < 0)
    {
        perror("tcsetpgrp");
        return;
    }

    if (execl("/bin/dash", "-/bin/dash", NULL) < 0)
    {
        perror("exec");
    }
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

    option_verbose = 1;

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

    int devfd = open("/dev", O_RDONLY | O_CLOEXEC);
    int sysfsfd = open("/sys", O_RDONLY | O_CLOEXEC);

    if (devfd < 0 || sysfsfd < 0)
    {
        perror("Failed opening old mounts");
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
        fprintf(stderr, "bootstrap-init: root mounted, remounting dev and sysfs\n");

    if (fmount(devfd, "/dev") < 0 || fmount(sysfsfd, "/sys") < 0)
    {
        perror("fmount");
        fprintf(stderr, "bootstrap-init: Mounting devfs and sysfs failed\n");
        return 1;
    }

    if (option_verbose)
        fprintf(stderr, "bootstrap-init: root mounting done, exec'ing the new init\n");

    if (execve("/sbin/init", argv, environ) < 0)
    {
        perror("Failed to execute /sbin/init");
        drop_to_rescue_sh();
        return 1;
    }
}
