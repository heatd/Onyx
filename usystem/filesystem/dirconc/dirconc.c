/*
 * Concurrent directory operations test.
 *
 * Your system should survive this (without leaving a corrupted file
 * system behind) once the file system assignment is complete.
 */

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <pthread.h>

#define NTRIES    10000	/* loop count */
#define NPROCS    10	/* actually totals 4x this +1 processes */

#define TESTDIR   "dirconc"
#define NNAMES    4
#define NAMESIZE  32

////////////////////////////////////////////////////////////

static const char *const names[NNAMES] = {
	"aaaa", 
	"bbbb",
	"cccc", 
	"dddd",
};

static
void
choose_name(char *buf, size_t len)
{
	const char *a, *b, *c;

	a = names[random()%NNAMES];
	if (random()%2==0) {
		snprintf(buf, len, "%s", a);
		return;
	}
	b = names[random()%NNAMES];
	if (random()%2==0) {
		snprintf(buf, len, "%s/%s", a, b);
		return;
	}
	c = names[random()%NNAMES];
	snprintf(buf, len, "%s/%s/%s", a, b, c);
}

////////////////////////////////////////////////////////////

/*
 * The purpose of this is to be atomic. In our world, straight
 * printf tends not to be.
 */
static
void
#ifdef __GNUC__
	__attribute__((__format__(__printf__, 1, 2)))
#endif
say(const char *fmt, ...)
{
	char buf[512];
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);
	write(STDOUT_FILENO, buf, strlen(buf));
}

////////////////////////////////////////////////////////////

static
void
dorename(const char *name1, const char *name2)
{
	if (rename(name1, name2) < 0) {
		switch (errno) {
		    case ENOENT:
		    case ENOTEMPTY:
		    case EINVAL:
			break;
		    default:
		      say("pid %d: rename %s -> %s: %s\n", 
		          getpid(), name1, name2, strerror(errno));
			break;
		}
	}
}

static
void
domkdir(const char *name)
{
	if (mkdir(name, 0775)<0) {
		switch (errno) {
		    case ENOENT:
		    case EEXIST:
			break;
		    default:
		      say("pid %d: mkdir %s: %s\n",
		          getpid(), name, strerror(errno));
			break;
		}
	}
}

static
void
dormdir(const char *name)
{
	if (rmdir(name)<0) {
		switch (errno) {
		    case ENOENT:
		    case ENOTEMPTY:
		    case EINVAL:
			break;
		    default:
		      say("pid %d: rmdir %s: %s\n",
		          getpid(), name, strerror(errno));
			break;
		}
	}
}

static
void
cleanup_rmdir(const char *name)
{
	if (rmdir(name)<0) {
		switch (errno) {
		    case ENOENT:
			break;
		    default:
			say("cleanup (pid %d): rmdir %s: %s\n",
			    getpid(), name, strerror(errno));
			break;
		}
	}
}

////////////////////////////////////////////////////////////

static
void
rename_proc(void)
{
	char name1[NAMESIZE], name2[NAMESIZE];
	int ct;
	
	for (ct=0; ct<NTRIES; ct++) {
		if ((ct % 100) == 0)
			say("rename %d (%lx)\n", ct, (unsigned long)pthread_self());
		choose_name(name1, sizeof(name1));
		choose_name(name2, sizeof(name2));
		//say("pid %2d: rename %s -> %s\n", (int)getpid(), name1, name2);
		dorename(name1, name2);
	}
}

static
void
mkdir_proc(void)
{
	char name[NAMESIZE];
	int ct;
	
	for (ct=0; ct<NTRIES; ct++) {
		if ((ct % 100) == 0)
			say("mkdir %d (%lx)\n", ct, (unsigned long)pthread_self());
		choose_name(name, sizeof(name));
		//say("pid %2d: mkdir  %s\n", (int)getpid(), name);
		domkdir(name);
	}
}

static
void
rmdir_proc(void)
{
	char name[NAMESIZE];
	int ct;

	for (ct=0; ct<NTRIES; ct++) {
		if ((ct % 100) == 0)
			say("rmdir %d (%lx)\n", ct, (unsigned long)pthread_self());
		choose_name(name, sizeof(name));
		//say("pid %2d: rmdir  %s\n", (int)getpid(), name);
		dormdir(name);
	}
}

////////////////////////////////////////////////////////////

static void *
startit(void *arg)
{
	void (*func)(void) = arg;

	(*func)();
	return 0;
}

static
int
dofork(void (*func)(void), pthread_t *thread)
{
	int error;

	error = pthread_create(thread, 0, &startit, func);
	if (error) {
		say("pthread_create: %s\n", strerror(error));
		exit(1);
	}

    return 0;
}

static
void
run(void)
{
	pthread_t threads[NPROCS*4];
	size_t i;
	int error;

	for (i = 0; i < NPROCS; i++) {
		say("fork %zu (+ 1, + 2, + 3)\n", i);
		dofork(mkdir_proc, &threads[i*4]);
		dofork(mkdir_proc, &threads[i*4+1]);
		dofork(rename_proc, &threads[i*4+2]);
		dofork(rmdir_proc, &threads[i*4+3]);
	}

	for (i = 0; i < NPROCS*4; i++) {
		say("join %zu (%lx)\n", i, threads[i]);
		error = pthread_join(threads[i], 0);
		if (error) {
			say("pthread_join: %s\n", strerror(error));
			exit(2);
		}
	}
}

////////////////////////////////////////////////////////////

static
void
setup(const char *fs)
{
	if (chdir(fs)<0) {
		say("chdir: %s: %s\n", fs, strerror(errno));
		exit(1);
	}
	if (mkdir(TESTDIR, 0775)<0) {
		say("mkdir: %s: %s\n", TESTDIR, strerror(errno));
		exit(1);
	}
	if (chdir(TESTDIR)<0) {
		say("chdir: %s: %s\n", TESTDIR, strerror(errno));
		exit(1);
	}
}

static
void
recursive_cleanup(const char *sofar, int depth)
{
	char buf[NAMESIZE*32];
	int i;
	
	for (i=0; i<NNAMES; i++) {
		snprintf(buf, sizeof(buf), "%s/%s", sofar, names[i]);
		if (rmdir(buf)<0) {
			if (errno==ENOTEMPTY) {
				recursive_cleanup(buf, depth+1);
				cleanup_rmdir(buf);
			}
			else if (errno!=ENOENT) {
				say("cleanup (pid %d): rmdir %s: %s\n", 
				    getpid(), buf, strerror(errno));
			}
		}
	}
}

static
void
cleanup(void)
{
	recursive_cleanup(".", 0);
	
	chdir("..");
	cleanup_rmdir(TESTDIR);
}

////////////////////////////////////////////////////////////

int
main(int argc, char *argv[])
{
	const char *fs;
	long seed = 0;
	
	say("Concurrent directory ops test\n");
	
	if (argc==0 || argv==NULL) {
		say("Warning: argc is 0 - assuming you mean to run on lhd1: "
		    "with seed 0\n");
		fs = "lhd1:";
	}
	else if (argc==2) {
		fs = argv[1];
	}
	else if (argc==3) {
		fs = argv[1];
		seed = atoi(argv[2]);
	}
	else {
		say("Usage: dirconc filesystem [random-seed]\n");
		exit(1);
	}
	
	srandom(seed);
	setup(fs);
	say("Starting in %s/%s\n", fs, TESTDIR);
	
	run();
	
	say("Cleaning up\n");
	cleanup();
	
	return 0;
}
