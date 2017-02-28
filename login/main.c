/*----------------------------------------------------------------------
 * Copyright (C) 2016, 2017 Pedro Falcato
 *
 * This file is part of Onyx, and is made available under
 * the terms of the GNU General Public License version 2.
 *
 * You can redistribute it and/or modify it under the terms of the GNU
 * General Public License version 2 as published by the Free Software
 * Foundation.
 *----------------------------------------------------------------------*/
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>

#include <sys/syscall.h>
struct user
{
	/* Next member of the user structure */
	struct user *next;
	/* Username */
	char *username;
	/* Password */
	char *password;
	/* GID and UID */
	gid_t gid;
	uid_t uid;
};

char *program_name = NULL;
struct user *users = NULL;

struct user *find_user_by_name(char *username)
{
	for(struct user *u = users; u; u = u->next)
	{
		if(strcmp(u->username, username) == 0)
			return u;
	}
	return NULL;
}
char *copy_string(char *str)
{
	char *ret = malloc(strlen(str) + 1);
	if(!ret)
		return NULL;
	strcpy(ret, str);
	return ret;
}
int insert_user(char *username, char *passwd, gid_t gid, uid_t uid)
{
	if(!username)
		return 1;
	if(!passwd)
		return 1;

	struct user *u = users;

	if(!u)
	{
		users = malloc(sizeof(struct user));
		if(!users)
			return 1;
		users->username = copy_string(username);
		users->password = copy_string(passwd);
		users->gid = gid;
		users->uid = uid;
		users->next = NULL;

		return 0;
	}

	for(; u->next; u = u->next);
	u->next = malloc(sizeof(struct user));
	if(!u->next)
		return 1;
	u->next->username = copy_string(username);
	u->next->password = copy_string(passwd);
	u->next->gid = gid;
	u->next->uid = uid;
	u->next->next = NULL;
	return 0;
}
int setup_users()
{
	/* Open /etc/passwd */
	FILE *fp = fopen("/etc/passwd", "r");
	if(!fp)
	{
		perror(program_name);
		return 1;
	}
	/* Allocate a buffer */
	char *read_buffer = malloc(1024);
	if(!read_buffer)
	{
		fclose(fp);
		perror(program_name);
		return 1;
	}
	memset(read_buffer, 0, 1024);

	while(fgets(read_buffer, 1024, fp) != NULL)
	{
		if(strlen(read_buffer) == '\0')
			goto func_exit;
		char *pos;
		if((pos = strchr(read_buffer, '\n')))
    			*pos = '\0';
		/* Parse the line */
		char *username = strtok(read_buffer, ":");
		char *uid_s = strtok(NULL, ":");
		char *gid_s = strtok(NULL, ":");
		char *passwd = strtok(NULL, ":");

		if(!uid_s)
		{
			fclose(fp);
			free(read_buffer);
			return 1;
		}
		if(!gid_s)
		{
			fclose(fp);
			free(read_buffer);
			return 1;
		}
		char *errorptr = NULL;
		gid_t gid = strtol(gid_s, &errorptr, 10);

		if(*errorptr != '\0')
		{
			fclose(fp);
			free(read_buffer);
			return 1;
		}
		errorptr = NULL;
		uid_t uid = strtol(uid_s, &errorptr, 10);

		if(*errorptr != '\0')
		{
			fclose(fp);
			free(read_buffer);
			return 1;
		}
		if(insert_user(username, passwd, gid, uid) == 1)
		{
			fclose(fp);
			free(read_buffer);
			return 1;
		}
	}
func_exit:
	/* Close the used registers */
	fclose(fp);
	free(read_buffer);
	return 0;
}
/* Set the uid and gid */
void switch_users(gid_t gid, uid_t uid)
{
	syscall(SYS_setuid, uid);
	syscall(SYS_setgid, gid);
}
/* TODO: Construct the envp properly */
char **args;
int main(int argc, char **argv, char **envp)
{
	args = argv;

	program_name = argv[0];
	printf("%s: ", argv[0]);
	fflush(stdout);
	char *buf = malloc(1024);
	if(!buf)
		return 1;

	/* Setup the internal user-password-uid-gid structures */
	if(setup_users() == 1)
	{
		return 1;
	}
loop:
	printf("username:");
	fflush(stdout);

	fgets(buf, 1024, stdin);
	char *pos;
	if((pos = strchr(buf, '\n')))
    		*pos = '\0';
	/* Try to find the user */
	struct user *user = find_user_by_name(buf);
	if(!user)
	{
		printf("Unknown user! Try again.\n");
		goto loop;
	}
	printf("password:");
	fflush(stdout);
	memset(buf, 0, 1024);
	fgets(buf, 1024, stdin);
	if((pos = strchr(buf, '\n')))
    		*pos = '\0';
	if(strcmp(buf, user->password) != 0)
	{
		printf("Unknown password! Try again.\n", buf);
		goto loop;
	}
	switch_users(user->gid, user->uid);

	args[0] = "/bin/sh";
	extern char **environ;
	execve("/bin/sh", args, environ);
	while(1);
	return 0;
}
