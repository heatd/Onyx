/*
* Copyright (c) 2018 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <err.h>
#include <stdbool.h>
#include <fcntl.h>
#include <unistd.h>
#include <pthread.h>

#include <memory>
#include <iostream>

#include <display.h>
#include <window.h>
#include <server.h>

#include <drm/drm.h>

#include <sys/wait.h>
#include <sys/mman.h>


#define COLOR_BLACK	0x00000000

#define DESKTOP_ENVIRONMENT_NAME	"/usr/bin/singularity"
#define ERR_EXEC_FAILED			126

void *ServerThread(void *ptr)
{
	Server *sv = (Server *) ptr;

	sv->handle_events();

	return nullptr;
}

int main(int argc, char **argv, char **envp)
{
	std::cout << "wserver - window server\n";
	std::shared_ptr<Display> disp;

	try
	{
		disp = std::make_shared<Display>();
	}
	catch(const std::exception& e)
	{
		std::cerr << e.what() << '\n';
		perror("errno value");
		return 1;
	}

	Server server(disp);

	disp->Clear(COLOR_BLACK);

	/* Fork and execute the desktop environment */
	pid_t child_pid = fork();

	if(child_pid < 0)
	{
		perror("fork");
	}
	else if(child_pid == 0)
	{
		if(execl(DESKTOP_ENVIRONMENT_NAME, DESKTOP_ENVIRONMENT_NAME) < 0)
			exit(ERR_EXEC_FAILED);
	}

	pthread_t thread;
	if(pthread_create(&thread, nullptr, ServerThread, &server) < 0)
		perror("pthread_create");
	int status;

	waitpid(-1, &status, 0);

	if(WEXITSTATUS(status) == ERR_EXEC_FAILED)
	{
		std::cout << "waitpid: execl failed\n";
		while(1);
		return 1;
	}

	std::cout << "wserver - debug sleep\n";
	sleep(10000000);

	return 0;
}
