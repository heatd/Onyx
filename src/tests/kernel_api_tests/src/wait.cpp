/*
* Copyright (c) 2020 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <unistd.h>
#include <fcntl.h>
#include <cstring>
#include <string>
#include <signal.h>

#include "../include/child_process_helper.h"

#include <gtest/gtest.h>
#include <sys/wait.h>

TEST(WaitStatus, NormalExit)
{
	ChildProcessHelper helper;

	auto wstatus = helper.execute_process([](const ChildProcessHelper &){},
	[](const ChildProcessHelper& h) -> int
	{
		return 14;
	});

	EXPECT_TRUE(WIFEXITED(wstatus));
	EXPECT_EQ(WEXITSTATUS(wstatus), 14);
}

TEST(WaitStatus, AbnormalExit)
{
	ChildProcessHelper helper;

	auto wstatus = helper.execute_process([](const ChildProcessHelper &){},
	[](const ChildProcessHelper& h) -> int
	{
		abort();
	});

	EXPECT_TRUE(WIFSIGNALED(wstatus));
	EXPECT_EQ(WTERMSIG(wstatus), SIGABRT);
}

void sigchld_handler(int signum, siginfo_t *si, void *mctx)
{
}

TEST(SigChld, SigChldInfoExit)
{
	struct sigaction sa;
	sa.sa_flags = SA_RESETHAND | SA_SIGINFO;
	sa.sa_sigaction = sigchld_handler;

	ASSERT_EQ(sigaction(SIGCHLD, &sa, nullptr), 0);

	int pid = fork();
	ASSERT_NE(pid, -1);

	if(pid != 0)
	{
		siginfo_t info;
		sigset_t set;
		sigemptyset(&set);
		sigaddset(&set, SIGCHLD);
	
		ASSERT_EQ(sigtimedwait(&set, &info, nullptr), SIGCHLD);

		EXPECT_EQ(info.si_pid, pid);
		EXPECT_EQ(info.si_uid, getuid());
		EXPECT_EQ(info.si_status, 12);
		EXPECT_EQ(info.si_code, CLD_EXITED);
		wait(nullptr);
	}
	else
	{
		exit(12);
	}
}

TEST(WaitStatus, SigStopCont)
{
	Waiter w;
	pid_t pid = fork();

	ASSERT_NE(pid, -1);

	if(pid == 0)
	{
		raise(SIGSTOP);
		w.Wait();
		exit(0);
	}
	else
	{
		int wstatus;
		ASSERT_EQ(waitpid(pid, &wstatus, WSTOPPED), pid);

		EXPECT_TRUE(WIFSTOPPED(wstatus));
		EXPECT_TRUE(WSTOPSIG(wstatus) == SIGSTOP);
		EXPECT_TRUE(waitpid(pid, &wstatus, WSTOPPED | WNOHANG) == 0);
		kill(pid, SIGCONT);

		EXPECT_EQ(waitpid(pid, &wstatus, WCONTINUED), pid);
		EXPECT_TRUE(WIFCONTINUED(wstatus));

		EXPECT_TRUE(waitpid(pid, &wstatus, WCONTINUED | WNOHANG) == 0);

		w.Wake();
		EXPECT_EQ(waitpid(pid, &wstatus, 0), pid);

		EXPECT_TRUE(WIFEXITED(wstatus));
		EXPECT_EQ(WEXITSTATUS(wstatus), 0);
	}
}

TEST(WaitStatus, SigStopKill)
{
	Waiter w;
	pid_t pid = fork();

	ASSERT_NE(pid, -1);

	if(pid == 0)
	{
		raise(SIGSTOP);
		w.Wait();
		exit(0);
	}
	else
	{
		int wstatus;
		ASSERT_EQ(waitpid(pid, &wstatus, WSTOPPED), pid);

		EXPECT_TRUE(WIFSTOPPED(wstatus));
		EXPECT_TRUE(WSTOPSIG(wstatus) == SIGSTOP);
		EXPECT_TRUE(waitpid(pid, &wstatus, WSTOPPED | WNOHANG) == 0);
		kill(pid, SIGKILL);

		w.Wake();
		EXPECT_EQ(waitpid(pid, &wstatus, 0), pid);

		EXPECT_TRUE(WIFSIGNALED(wstatus));
		EXPECT_EQ(WTERMSIG(wstatus), SIGKILL);
	}
}
