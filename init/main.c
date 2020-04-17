/*
* Copyright (c) 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#define _GNU_SOURCE
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <unwind.h>
#include <fcntl.h>
#include <time.h>
#include <ctype.h>

#include <sys/stat.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/mount.h>

#include "init.h"
extern char **environ;

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
	if(c >= 48 && c <= 57)
		return 1;
	return 0;
}

char *copy_until_newline(char *s)
{
	char *str = s;
	size_t len = 0;
	while(*str != '\n' && *str != '\0')
	{
		len++;
		str++;
	}
	char *buffer = malloc(len + 1);
	memset(buffer, 0, len + 1);
	char *ret = buffer;
	str = s;
	for(; len; len--)
		*buffer++ = *str++;
	return ret;
}

void insmod(const char *path, const char *name)
{
	syscall(SYS_insmod, path, name);
}

int fmount(int fd, char *path)
{
	if(syscall(SYS_fmount, fd, path))
		return -1;
	return 0;
}

int mount_filesystems(void)
{
	FILE *fp = fopen("/etc/fstab", "r");
	if(!fp)
	{
		perror("/etc/fstab");
		return 1;
	}

	char *read_buffer = malloc(1024);
	if(!read_buffer)
	{
		perror(__func__);
		fclose(fp);
		return 1;
	}

	memset(read_buffer, 0, 1024);
	int fd = open("/dev", O_RDONLY);
	int sysfs_fd = open("/sys", O_RDONLY);

	while(fgets(read_buffer, 1024, fp) != NULL)
	{
		int arg_num = 0;
		char *pos;
		char *source = NULL;
		char *target = NULL;
		char *filesystem_type = NULL;
		/* If this line is a comment, ignore it */
		if(*read_buffer == '#')
			continue;
		if(strlen(read_buffer) == '\0')
			goto func_exit;
		/* Delete the \n that might exist */
		if((pos = strchr(read_buffer, '\n')))
    			*pos = '\0';
		char *str = strtok(read_buffer, " \t");
		while(str != NULL)
		{
			if(arg_num == 0)
			{
				source = str;
			}
			else if(arg_num == 1)
			{
				target = str;
			}
			else if(arg_num == 2)
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

		if(mount(source, target, filesystem_type, 0, NULL) < 0)
		{
			printf("init: failed to mount %s\n", source);
			perror("mount");
			free(read_buffer);
			fclose(fp);
			close(sysfs_fd);
			close(fd);
			return 1;
		}
	}
	/* Now, mount /dev on root again */
	fmount(fd, "/dev");
	/* Remount /sys too */
	fmount(sysfs_fd, "/sys");

	/* Create /dev/shm */
	mkdir("/dev/shm", 0666);
func_exit:
	free(read_buffer);
	close(fd);
	close(sysfs_fd);
	fclose(fp);
	return 0;
}

bool fail_on_mount_error = true;

void segv(int sig, siginfo_t *info, void *ucontext)
{
	ucontext_t *ctx = ucontext;
	//printf("Fault at %lx\n", info->si_addr);
	//printf("Sent from %d\n", info->si_code);
}

#include <pthread.h>

void *func(void *f)
{
	while(true) {}
}

void signal_test()
{
	pid_t p = fork();

	if(p == 0)
	{
		/*pthread_t new_thread;
		if(pthread_create(&new_thread, NULL, func, NULL) < 0)
			perror("pthread_create");*/
		
		sigset_t mask;
		sigaddset(&mask, SIGSEGV);
		sigprocmask(SIG_SETMASK, &mask, NULL);
		/*struct sigaction sa;
		sa.sa_flags = SA_SIGINFO;
		sa.sa_sigaction = segv;

		sigaction(SIGSEGV, &sa, NULL);*/

		/*sigset_t set = {};
		siginfo_t info;
		sigaddset(&set, SIGSEGV);
		if(sigwaitinfo(&set, &info) < 0)
			perror("sigwaitinfo");*/
		//printf("Signalled - info code %d\n", info.si_code);
		/*sleep(2);

		if(sigpending(&mask) < 0)
			perror("sigpending");
		printf("Is segv pending? %u\n", sigismember(&mask, SIGSEGV));*/
		while(true) {}
	}
	else
	{
		printf("Sleeping 2 seconds and killing our child\n");
		sleep(1);
		kill(p, SIGSEGV);
		printf("Now, we're SIGCONTing it\n");
		sleep(1);
		//kill(p, SIGCONT);
	}

	while(true) {}
}

void mmap_test(void)
{
	int fd = open("/etc/init.d/targets/default.target", O_RDONLY);
	if(fd < 0)
	{
		perror("bad open");
		return;
	}

	volatile void *addr = mmap(NULL, 4096, PROT_WRITE | PROT_READ, MAP_PRIVATE, fd, 0);
	if(addr == MAP_FAILED)
	{
		perror("mmap");
		return;
	}

	printf("Here %s\n", addr);

	memset(addr, 0, 4096);
}

int main(int argc, char **argv, char **envp)
{
	int c;
	while((c = getopt(argc, argv, "m")) != -1)
	{
		switch(c)
		{
			case 'm':
			{
				fail_on_mount_error = false;
				break;
			}
		}
	}

	/* Check if we're actually the first process */
	pid_t p = getpid();
	if(p != 1)
		return 1;

	/* Load the needed kernel modules */
	load_modules();

	/* Mount filesystems */
	if(mount_filesystems() == 1)
	{
		if(fail_on_mount_error)
		{
			printf("init: Failed to mount filesystems - dumping into dash shell\n");
			chdir("/");
			if(execl("/bin/dash", "-/bin/dash", NULL) < 0)
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

	//signal_test();
	//mmap_test();

	/* Execute daemons */
	exec_daemons();
	/* Mask every signal */
	sigset_t set;
	sigfillset(&set);
	sigprocmask(SIG_SETMASK, &set, NULL);

	while(1)
	{
		if(waitpid(-1, NULL, WEXITED) < 0)
		{
			perror("waitpid");
			return 1;
		}
	}
	return 0;
}

void load_modules(void)
{
	/* Open the modules file */
	FILE *file = fopen("/etc/modules.load", "r");
	if(!file)
	{
		perror("/etc/modules.load");
		return;
	}

	char *buf = malloc(1024);
	if(!buf)
	{
		fclose(file);
		return;
	}
	memset(buf, 0, 1024);

	/* At every line there's a module name. Get it, and insmod it */
	while(fgets(buf, 1024, file) != NULL)
	{
		buf[strlen(buf)-1] = '\0';
		if(buf[0] == '\0')
			continue;

		char *path = malloc(strlen(MODULE_PREFIX) + strlen(buf) + 1 + strlen(MODULE_EXT));
		if(!path)
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

void setup_hostname()
{
	/* Open the /etc/hostname file */
	FILE *file = fopen("/etc/hostname", "r");
	if(!file)
	{
		perror("/etc/hostname");

		printf("Hostname not found - using 'localhost'\n");
		sethostname("localhost", strlen("localhost"));

		return;
	}
	char *buf = malloc(1024);
	if(!buf)
	{
		fclose(file);
		return;
	}
	memset(buf, 0, 1024);
	/* There should only be one line in the file(that contains the hostname itself),
		so we only need one fgets() */
	fgets(buf, 1024, file);

	buf[strlen(buf)-1] = '\0';	
	if(buf[0] == '\0')
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
