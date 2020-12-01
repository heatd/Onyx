/*
* Copyright (c) 2020 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#ifndef CHILD_PROCESS_HELPER_H
#define CHILD_PROCESS_HELPER_H

#include "waiter.h"
#include <functional>
#include <unistd.h>
#include <stdexcept>
#include <gtest/gtest.h>
#include <string>

/* Forks and executes some code in the parent and some code in the child */
struct ChildProcessHelper
{
	Waiter w;
	pid_t pid;

	int operator()(std::function<void(const ChildProcessHelper&)> parent_code,
	               std::function<int(const ChildProcessHelper&)> child_code,
				   std::function<void(const ChildProcessHelper&)> post_wake_code =
				   std::function<void(const ChildProcessHelper&)>{[](const ChildProcessHelper&){}})
	{
		pid = fork();

		if(pid < 0)
		{
			throw std::runtime_error(std::string("fork error") + strerror(errno));
		}

		if(pid == 0)
		{
			w.Wait();
			exit(child_code(*this));
		}
		else
		{
			parent_code(*this);
			w.Wake();

			post_wake_code(*this);

			int wstatus;

			if(wait(&wstatus) < 0)
				throw std::runtime_error("wait error");
			
			return WEXITSTATUS(wstatus);
		}
	}
};

#endif
