/*
* Copyright (c) 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <unwind.h>
#include <fcntl.h>
#include <time.h>
#include <ctype.h>

#include <sys/time.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <sys/utsname.h>

#define MODULE_PREFIX "/usr/lib/modules/"
#define MODULE_EXT    ".kmod"
extern char **environ;
void load_modules();
void setup_hostname();
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
int get_ring_level()
{
	/* Open the config */
	FILE *f = fopen("/etc/init.d/init.config", "rw");
	if(!f)
	{
		perror("/etc/init.d/init.config");
		return -1;
	}
	char *buf = malloc(1024);
	if(!buf)
	{
		perror("/sbin/init");
		fclose(f);
		return -1;
	}
	memset(buf, 0, 1024);
	int ringlevel = 0;
	/* Now lets loop through the file, and get the default ring level */
	fgets(buf, 1024, f);
	if(memcmp(buf, "defaultrl:", strlen("defaultrl:")) == 0)
	{
		/* If the argument after 'defaultrl:' isn't a number, throw a parsing error and return 1 */
		if(sscanf(buf + strlen("defaultrl:"), "%d", &ringlevel) == 0)
		{
			printf("syntax error: at '%c'\n", *(buf + strlen("defaultrl:")));
			free(buf);
			fclose(f);
			return -1;
		}
		else
		{
			fclose(f);
			free(buf);
			/* It's a number, use tonum(3), as ring levels are from 0-6 */
			return ringlevel;
		}
	}
	/* Free up the resources we've just used */
	fclose(f);
	free(buf);
	return -1;
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
		return 1;
	}
	memset(read_buffer, 0, 1024);
	int fd = open("/dev", O_RDONLY);
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
			perror("");
			free(read_buffer);
			fclose(fp);
			return 1;
		}
	}
	/* Now, mount /dev on root again */
	fmount(fd, "/dev");
func_exit:
	free(read_buffer);
	close(fd);
	fclose(fp);
	return 0;
}
int main(int argc, char **argv, char **envp)
{
	/* Check if we're actually the first process */
	pid_t p = getpid();
	if(p != 1)
		return 1;

	/* Load the needed kernel modules */
	load_modules();

	/* Setup the hostname */
	setup_hostname();

	/* Mount filesystems */
	if(mount_filesystems() == 1)
		return 1;
	/* Read the config files, and find the startup program */
	int ringlevel = get_ring_level();
	if(ringlevel < 0)
		err(1, "Failed to get the ring level!\n");
	/* Allocate a buffer for the filename */
	char *filename = malloc(strlen(prefix) + 4);
	if(!filename)
		return 1;
	strcpy(filename, prefix);
	/*  Edit in the ring level */
	filename[14] = ringlevel + '0';
	/* Open the script file */
	FILE *f = fopen(filename, "r");
	if(!f)
	{
		printf("%s: No such file or directory!\n", filename);
		free(filename);
		return 1;
	}

	char *buf = malloc(1024);
	if(!buf)
	{
		fclose(f);
		free(filename);
		return 1;
	}
	memset(buf, 0, 1024);
	fgets(buf, 1024, f);
	
	chdir("/");
	char *env[] = {"", NULL};
	char *shell = copy_until_newline(buf);
	char *args[] = {shell, "/etc/fstab", NULL};

	int pid = fork();

	if(pid == 0)
	{
		if(execve(shell, args, environ) < 0)
			perror("init: exec");
	}

	/* Mask every signal */
	sigset_t set;
	sigfillset(&set);
	sigprocmask(SIG_SETMASK, &set, NULL);
	while(1)
	{
		waitpid(-1, NULL, WEXITED);
	}
	return 0;
}
void load_modules()
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
	/* There should only be one line in the file(that contains the hostname itself), so we only need one fgets() */
	fgets(buf, 1024, file);

	buf[strlen(buf)-1] = '\0';	
	if(buf[0] == '\0')
	{
		printf("Hostname not found - using 'localhost'\n");
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
