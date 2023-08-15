// SPDX-License-Identifier: GPL-2.0-only
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

/* file_rcu - stress test file/file table rcu
 * Stress it by stressing two functions:
 * 1) file lookup in fstat
 * 2) file table expansion
 * 3) file close concurrently with lookup.
 */

#define THREADS 4
#define TIMEOUT 120

#define align_cache __attribute__((aligned(64)))

/* We use $THREADS for lookup (fstat), one for close (closes and opens randomly one of the lookup
 * threads' fd), and one for expansion (expands until it's not possible, then exits).
 */
static pthread_t threads[THREADS + 2];

struct lookup_thread_stats
{
    int lookups_succeeded;
    int lookups_failed;
} align_cache;

static struct lookup_thread_stats lookup_stats[THREADS] align_cache;
int expands_done align_cache = 0;
int closes_done align_cache = 0;

const int fd_base = 3;

static volatile sig_atomic_t should_stop = 0;

static void *lookup(void *arg)
{
    int fd = (int) (unsigned long) arg;
    int thread = fd - fd_base;

    while (!should_stop)
    {
        struct stat buf;
        if (fstat(fd, &buf) < 0)
        {
            // The only valid errno is a transient EBADF
            if (errno != EBADF)
                err(1, "fstat");
            lookup_stats[thread].lookups_failed++;
        }
        else
        {
            lookup_stats[thread].lookups_succeeded++;
        }
    }

    return NULL;
}

static void *close_files(void *p)
{
    (void) p;
    srand(time(NULL));

    while (!should_stop)
    {
        int fd = fd_base + (rand() % THREADS);
        close(fd);
        int st = open("/dev/null", O_RDWR | O_CLOEXEC);
        if (st < 0)
        {
            // We can get a transient EMFILE here from expand() taking up this fd.
            // That's no biggie.
            if (errno == EMFILE)
                continue;
            err(1, "open");
        }

        if (st != fd)
        {
            int st2 = 0;
            do
            {
                st2 = dup2(st, fd);
                if (st2 >= 0)
                    break;
                // Note: Linux can return EBUSY on a dup2 "race", so we must spin until we can get
                // rid of it.
            } while (st2 < 0 && errno == EBUSY);
            if (st2 < 0)
                err(1, "dup2");

            close(st);
        }

        closes_done++;
    }

    return NULL;
}

static void *expand(void *p)
{
    (void) p;

    while (!should_stop)
    {
        int fd = open("/dev/null", O_RDWR | O_CLOEXEC);
        if (fd < 0)
        {
            if (errno != EMFILE)
                err(1, "open");
            else
                break;
        }

        expands_done++;
    }

    return NULL;
}

static void handle_alarm(int sig)
{
    (void) sig;
    should_stop = 1;
}

int main(int argc, char **argv)
{
    (void) argc, (void) argv;
    signal(SIGALRM, handle_alarm);
    alarm(TIMEOUT);

    for (int i = 0; i < THREADS; i++)
    {
        int fd = open("/dev/null", O_RDWR | O_CLOEXEC);
        if (fd < 0)
            err(1, "open");
        if (dup2(fd, fd_base + i) < 0)
            err(1, "dup2");
    }

    for (int i = 0; i < THREADS; i++)
    {
        if (pthread_create(&threads[i], NULL, lookup, (void *) (unsigned long) (i + fd_base)))
            err(1, "pthread_create");
    }

    if (pthread_create(&threads[THREADS], NULL, close_files, NULL))
        err(1, "pthread_create");

    if (pthread_create(&threads[THREADS + 1], NULL, expand, NULL))
        err(1, "pthread_create");

    for (int i = 0; i < THREADS + 2; i++)
    {
        pthread_join(threads[i], NULL);
    }

    printf("file_rcu stats:\n");
    printf("lookup:\n");
    for (int i = 0; i < THREADS; i++)
    {
        printf("\tthread %d: %d succeeded, %d failed (closed), %d total\n", i,
               lookup_stats[i].lookups_succeeded, lookup_stats[i].lookups_failed,
               lookup_stats[i].lookups_failed + lookup_stats[i].lookups_succeeded);
    }

    printf("close: %d closes done\n", closes_done);
    printf("expand: %d expands done\n", expands_done);

    return 0;
}
