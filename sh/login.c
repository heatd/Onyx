/*
* Copyright (c) 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <err.h>
#include <shell.h>
#include <login.h>

static _Bool is_login = false;
void tash_do_login(void)
{
	is_login = true;
	char *login_script_path = getenv("HOME");
	if(!login_script_path)
		login_script_path = DEFAULT_LOGIN_SCRIPT_PATH; /* If HOME isn't set, set shell_path with a hardcoded and known value */
	size_t buf_size = strlen(login_script_path) + strlen(TASH_LOGIN_SCRIPT);
	char *login_script = malloc(buf_size);
	if(!login_script)
	{
		err(1, "tash_do_login: no memory");
	}
	memset(login_script, 0, buf_size);
	strcpy(login_script, login_script_path);
	strcat(login_script, TASH_LOGIN_SCRIPT);
	printf("Login script: %s\n", login_script);
	int pid = fork();
	if(pid == 0)
	{
		char *argv[] = {login_script, NULL};
		if(execvp(login_script, argv) < 0)
			perror("execvp");
	}
}
_Bool tash_is_login(void)
{
	return is_login;
}