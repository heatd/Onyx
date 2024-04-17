/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (c) 2024 Pedro Falcato */
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <limits.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

const struct option long_options[] = {
    {"help", 0, NULL, 'h'},
    {"threads", required_argument, NULL, 't'},
    {},
};

void show_help(int flag)
{
    /* Return 1 if it was an invalid flag. */
    int ret = flag == '?';

    printf("Usage:\n   create_unlink_stress [options]\nOptions:\n"
           "   -h, --help     print help and exit\n"
           "   -t, --threads N Number of threads to use (default = 1)\n");

    exit(ret);
}

static unsigned int threads = 1;

void *thread_main(void *arg)
{
    char filename[NAME_MAX];
    unsigned int nr = (unsigned int) (unsigned long) arg;
    sprintf(filename, "stresstest%u", nr);

    /* Initial unlink of this file */
    unlink(filename);

    for (;;)
    {
        int fd = open(filename, O_RDWR | O_CREAT | O_EXCL, 0666);
        if (fd < 0)
            err(1, "open %s", filename);
        /* Write some sample data into it */
        ssize_t st = write(fd, filename, strlen(filename));
        if (st < 0)
            err(1, "write");
        close(fd);

        if (unlink(filename) < 0)
            err(1, "unlink");
    }

    return NULL;
}

static void destroy_all(void)
{
    for (unsigned int i = 0; i < threads; i++)
    {
        char filename[NAME_MAX];
        sprintf(filename, "stresstest%u", i);
        unlink(filename);
    }
}

static void destroy_all_sig(int sig)
{
    (void) sig;
    destroy_all();
    _exit(0);
}

int main(int argc, char **argv)
{
    int indexptr = 0;
    int flag = 0;
    atexit(destroy_all);
    signal(SIGINT, destroy_all_sig);
    signal(SIGQUIT, destroy_all_sig);

    while ((flag = getopt_long(argc, argv, "t:h", long_options, &indexptr)) != -1)
    {
        switch (flag)
        {
            case 't':
                errno = 0;
                threads = strtoul(optarg, NULL, 0);
                if (errno == ERANGE || threads == 0)
                {
                    printf("create_unlink_stress: Threads number out of range [1, UINT_MAX]\n");
                    return 1;
                }

                break;

            case 'h':
            case '?':
                show_help(flag);
                break;
        }
    }

    pthread_t *ids = calloc(threads, sizeof(pthread_t));
    if (!ids)
        err(1, "calloc");

    for (unsigned int i = 0; i < threads; i++)
    {
        int st = pthread_create(&ids[i], NULL, thread_main, (void *) (unsigned long) i);
        if (st)
            err(1, "pthread_create");
    }

    for (unsigned int i = 0; i < threads; i++)
        pthread_join(ids[i], NULL);
}
