/*
 * Copyright (c) 2017 - 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#define _GNU_SOURCE
#include <ctype.h>
#include <fcntl.h>
#include <getopt.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <unwind.h>

#include "init.h"

void load_modules(void);
void setup_hostname(void);

/* x is a placeholder */
char *prefix = "/etc/init.d/rcx.d";

int tonum(int c)
{
    return c - '0';
}

int isnum(int c)
{
    if (c >= 48 && c <= 57)
        return 1;
    return 0;
}

char *copy_until_newline(char *s)
{
    char *str = s;
    size_t len = 0;
    while (*str != '\n' && *str != '\0')
    {
        len++;
        str++;
    }
    char *buffer = malloc(len + 1);
    memset(buffer, 0, len + 1);
    char *ret = buffer;
    str = s;
    for (; len; len--)
        *buffer++ = *str++;
    return ret;
}

void insmod(const char *path, const char *name)
{
    syscall(SYS_insmod, path, name);
}

int fmount(int fd, char *path)
{
    if (syscall(SYS_fmount, fd, path))
        return -1;
    return 0;
}

int mount_autodetect(const char *dev, const char *mpoint)
{
    const char *fs_type[] = {"ext2"};

    for (int i = 0; i < 1; i++)
    {
        if (mount(dev, mpoint, fs_type[i], 0, NULL) == 0)
            return 1;
    }

    return 0;
}

int mount_filesystems(void)
{
    FILE *fp = fopen("/etc/fstab", "r");
    if (!fp)
    {
        perror("/etc/fstab");
        return 1;
    }

    char *read_buffer = malloc(1024);
    if (!read_buffer)
    {
        perror(__func__);
        fclose(fp);
        return 1;
    }

    memset(read_buffer, 0, 1024);

    while (fgets(read_buffer, 1024, fp) != NULL)
    {
        int arg_num = 0;
        char *pos;
        char *source = NULL;
        char *target = NULL;
        char *filesystem_type = NULL;
        /* If this line is a comment, ignore it */
        if (*read_buffer == '#')
            continue;
        if (strlen(read_buffer) == '\0')
            goto func_exit;
        /* Delete the \n that might exist */
        if ((pos = strchr(read_buffer, '\n')))
            *pos = '\0';
        char *str = strtok(read_buffer, " \t");
        while (str != NULL)
        {
            if (arg_num == 0)
            {
                source = str;
            }
            else if (arg_num == 1)
            {
                target = str;
            }
            else if (arg_num == 2)
            {
                filesystem_type = str;
            }
            else
            {
                printf("init: /etc/fstab: malformed line\n");
                free(read_buffer);
                fclose(fp);
                return 1;
            }
            arg_num++;
            str = strtok(NULL, " \t");
        }

        if (!strcmp(target, "/"))
            continue;

        if (mount(source, target, filesystem_type, 0, NULL) < 0)
        {
            printf("init: failed to mount %s\n", source);
            perror("mount");
            free(read_buffer);
            fclose(fp);
            return 1;
        }
    }

    /* Create /dev/shm */
    mkdir("/dev/shm", 0666);
func_exit:
    free(read_buffer);
    fclose(fp);
    return 0;
}

bool fail_on_mount_error = true;

struct option long_opts[] = {{NULL, 0, 0, 0}};

int main(int argc, char **argv)
{
    int c;
    int long_idx;

    opterr = 0;

    while ((c = getopt_long_only(argc, argv, "m", long_opts, &long_idx)) != -1)
    {
        switch (c)
        {
            case 'm': {
                fail_on_mount_error = false;
                break;
            }
        }
    }

    /* Check if we're actually the first process */
    pid_t p = getpid();
    if (p != 1)
        return 1;

    // First, (try to) create /dev if it doesn't exist
    mkdir("/dev", 0755);

    // Mount devfs
    if (mount("none", "/dev", "devfs", 0, NULL) < 0)
        return 1;

    // Open fd 0, 1, 2

    int flags[] = {O_RDONLY, O_WRONLY, O_WRONLY};

    for (int i = 0; i < 3; i++)
    {
        int fd = open("/dev/console", flags[i] | O_NOCTTY);

        if (fd < 0)
            return 1;

        dup2(fd, i);

        if (fd != i)
            close(fd);
    }

    // Standard streams set up!

#if 0
	struct memstat ostat;
	syscall(SYS_memstat, &ostat);

	int pid = fork();
	if(pid != 0)
	{
		sleep(1);

		struct memstat stat;
		syscall(SYS_memstat, &stat);
		printf("Allocated: %u\n", stat.allocated_pages);
		printf("Old allocated: %u\n", ostat.allocated_pages);
	}
	else if(pid == 0)
	{
		exit(0);
	}
#endif

    /* Load the needed kernel modules */
    load_modules();

    bool is_livecd = access("/etc/livecd", R_OK) == 0;

    /* Mount filesystems */
    if (!is_livecd && mount_filesystems() == 1)
    {
        if (fail_on_mount_error)
        {
            printf("init: Failed to mount filesystems - dumping into dash shell\n");
            chdir("/");
            tcsetpgrp(0, getpid());
            if (execl("/bin/dash", "-/bin/dash", NULL) < 0)
            {
                perror("exec error");
                return 1;
            }
        }
        else
            printf("mount errors: proceeding carefully.\n");
    }

    /* Setup the hostname */
    setup_hostname();

    /* Execute daemons */
    int st;

    if ((st = exec_daemons()) != 0)
    {
        printf("exec_daemons: error %d\n", st);
        return 1;
    }

    /* Mask every signal */
    sigset_t set;
    sigfillset(&set);
    sigprocmask(SIG_SETMASK, &set, NULL);

    for (;;)
    {

        int wstatus;
        pid_t pid;

        if ((pid = waitpid(-1, &wstatus, WEXITED)) < 0)
        {
            perror("waitpid");
            return 1;
        }

        struct daemon *daemon_info = get_daemon_from_pid(pid);

        if (!daemon_info)
        {
            // Not a registered daemon, ignore the exit status.
            continue;
        }

        if (WIFEXITED(wstatus) && WEXITSTATUS(wstatus) != 0)
        {
            fprintf(stderr, "init: pid %d (%s) exited with fatal status %d\n", pid,
                    daemon_info->name, WEXITSTATUS(wstatus));
        }
        else if (WIFSIGNALED(wstatus))
        {
            int termsig = WTERMSIG(wstatus);
            fprintf(stderr, "init: pid %d (%s) exited with fatal signal %d (%s)\n", pid,
                    daemon_info->name, termsig, strsignal(termsig));
        }

        // TODO: Deregister the daemon
    }
    return 0;
}

void load_modules(void)
{
    /* Open the modules file */
    FILE *file = fopen("/etc/modules.load", "r");
    if (!file)
    {
        perror("/etc/modules.load");
        return;
    }

    char *buf = malloc(1024);
    if (!buf)
    {
        fclose(file);
        return;
    }
    memset(buf, 0, 1024);

    /* At every line there's a module name. Get it, and insmod it */
    while (fgets(buf, 1024, file) != NULL)
    {
        buf[strlen(buf) - 1] = '\0';
        if (buf[0] == '\0')
            continue;

        char *path = malloc(strlen(MODULE_PREFIX) + strlen(buf) + 1 + strlen(MODULE_EXT));
        if (!path)
        {
            free(buf);
            fclose(file);
            return;
        }

        strcpy(path, MODULE_PREFIX);
        strcat(path, buf);
        strcat(path, MODULE_EXT);
        printf("Loading %s (path %s)\n", buf, path);
        insmod(path, buf);
    }

    free(buf);
    fclose(file);
}

void setup_hostname(void)
{
    /* Open the /etc/hostname file */
    FILE *file = fopen("/etc/hostname", "r");
    if (!file)
    {
        perror("/etc/hostname");

        printf("Hostname not found - using 'localhost'\n");
        sethostname("localhost", strlen("localhost"));

        return;
    }
    char *buf = malloc(1024);
    if (!buf)
    {
        fclose(file);
        return;
    }
    memset(buf, 0, 1024);
    /* There should only be one line in the file(that contains the hostname itself),
        so we only need one fgets() */
    fgets(buf, 1024, file);

    buf[strlen(buf) - 1] = '\0';
    if (buf[0] == '\0')
    {
        printf("Bad /etc/localhost - using 'localhost'\n");
        sethostname("localhost", strlen("localhost"));
        setenv("HOSTNAME", "localhost", 1);
    }
    else
    {
        sethostname(buf, strlen(buf));
        setenv("HOSTNAME", buf, 1);
    }
    fclose(file);
    free(buf);
}
