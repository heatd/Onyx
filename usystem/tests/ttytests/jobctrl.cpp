// SPDX-License-Identifier: GPL-2.0-only
#include <err.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>

#include <stdexcept>
#include <string>

#include <gtest/gtest.h>

#include "pty.h"

#define JOBCTL_BAD_SETUP   2
#define JOBCTL_TEST_FAILED 1

TEST(jobctrl, sigtstp_works)
{
    pid_t pid = fork();
    ASSERT_NE(pid, -1);

    if (pid == 0)
    {
        /* Get a new session, open a pty pair */
        if (setsid() < 0)
            err(JOBCTL_BAD_SETUP, "setsid");
        pty_pair pair;
        pair.reopen_pty_with_ctty();
        /* Fork again... */
        pid = fork();
        if (pid < 0)
            err(JOBCTL_BAD_SETUP, "fork");
        if (pid == 0)
        {
            if (setpgrp() < 0)
                err(JOBCTL_BAD_SETUP, "setpgrp");

            /* Ignore TTOU temporarily, while we set the foreground pgrp */
            signal(SIGTTOU, SIG_IGN);
            tcsetpgrp(pair.pts_fd, getpgrp());
            signal(SIGTTOU, SIG_DFL);

            if (write(pair.ptm_fd, "\032", 1) < 0)
                err(JOBCTL_TEST_FAILED, "write");
            sleep(1);
            exit(JOBCTL_TEST_FAILED);
        }
        else
        {
            int wstatus;
            if (waitpid(pid, &wstatus, WSTOPPED) < 0)
                err(JOBCTL_BAD_SETUP, "waitpid");
            kill(pid, SIGKILL);
            exit(!(WIFSTOPPED(wstatus) && WSTOPSIG(wstatus) == SIGTSTP));
        }
    }
    else
    {
        int wstatus;
        if (waitpid(pid, &wstatus, WSTOPPED) < 0)
            err(JOBCTL_BAD_SETUP, "waitpid");
        EXPECT_TRUE(WIFEXITED(wstatus));
        EXPECT_EQ(WEXITSTATUS(wstatus), 0);
    }
}

TEST(jobctrl, ioctl_sigttou_works)
{
    pid_t pid = fork();
    ASSERT_NE(pid, -1);

    if (pid == 0)
    {
        /* Get a new session, open a pty pair */
        if (setsid() < 0)
            err(JOBCTL_BAD_SETUP, "setsid");
        pty_pair pair;
        pair.reopen_pty_with_ctty();
        /* Fork again... */
        pid = fork();
        if (pid < 0)
            err(JOBCTL_BAD_SETUP, "fork");
        if (pid == 0)
        {
            /* Clear TOSTOP */
            struct termios term;
            if (tcgetattr(pair.pts_fd, &term) < 0)
                err(JOBCTL_BAD_SETUP, "tcgetattr");
            term.c_lflag &= ~TOSTOP;
            if (tcsetattr(pair.pts_fd, TCSANOW, &term) < 0)
                err(JOBCTL_BAD_SETUP, "tcsetattr");

            if (setpgrp() < 0)
                err(JOBCTL_BAD_SETUP, "setpgrp");

            /* tcsetpgrp will raise SIGTTOU, *despite* TOSTOP */
            tcsetpgrp(pair.pts_fd, getpgrp());
            sleep(1);
            exit(JOBCTL_TEST_FAILED);
        }
        else
        {
            int wstatus;
            if (waitpid(pid, &wstatus, WSTOPPED) < 0)
                err(JOBCTL_BAD_SETUP, "waitpid");
            kill(pid, SIGKILL);
            exit(!(WIFSTOPPED(wstatus) && WSTOPSIG(wstatus) == SIGTTOU));
        }
    }
    else
    {
        int wstatus;
        if (waitpid(pid, &wstatus, WSTOPPED) < 0)
            err(JOBCTL_BAD_SETUP, "waitpid");
        EXPECT_TRUE(WIFEXITED(wstatus));
        EXPECT_EQ(WEXITSTATUS(wstatus), 0);
    }
}

TEST(jobctrl, write_sigttou)
{
    pid_t pid = fork();
    ASSERT_NE(pid, -1);

    if (pid == 0)
    {
        /* Get a new session, open a pty pair */
        if (setsid() < 0)
            err(JOBCTL_BAD_SETUP, "setsid");
        pty_pair pair;
        pair.reopen_pty_with_ctty();
        /* Fork again... */
        pid = fork();
        if (pid < 0)
            err(JOBCTL_BAD_SETUP, "fork");
        if (pid == 0)
        {
            /* Clear TOSTOP */
            struct termios term;
            if (tcgetattr(pair.pts_fd, &term) < 0)
                err(JOBCTL_BAD_SETUP, "tcgetattr");
            term.c_lflag &= ~TOSTOP;
            if (tcsetattr(pair.pts_fd, TCSANOW, &term) < 0)
                err(JOBCTL_BAD_SETUP, "tcsetattr");

            if (setpgrp() < 0)
                err(JOBCTL_BAD_SETUP, "setpgrp");

            /* write will *not* raise SIGTTOU, because TOSTOP is clear */
            signal(SIGTTOU, [](int) { _exit(JOBCTL_TEST_FAILED); });
            if (write(pair.pts_fd, "a", 1) != 1)
                exit(JOBCTL_TEST_FAILED);

            /* Reset TOSTOP */
            signal(SIGTTOU, SIG_IGN);
            term.c_lflag |= TOSTOP;
            if (tcsetattr(pair.pts_fd, TCSANOW, &term) < 0)
                err(JOBCTL_BAD_SETUP, "tcsetattr");
            /* "if TOSTOP is set and the process is ignoring the SIGTTOU signal or the writing
             * thread is blocking the SIGTTOU signal, the process is allowed to write to the
             * terminal and the SIGTTOU signal is not sent" */

            /* Test ignoring the signal */
            if (write(pair.pts_fd, "a", 1) != 1)
                exit(JOBCTL_TEST_FAILED);
            signal(SIGTTOU, SIG_DFL);

            /* Test blocking the signal (making sure it is *not* sent) */
            sigset_t set;
            sigemptyset(&set);
            sigaddset(&set, SIGTTOU);
            if (sigprocmask(SIG_BLOCK, &set, NULL) < 0)
                exit(JOBCTL_BAD_SETUP);

            if (write(pair.pts_fd, "a", 1) != 1)
                exit(JOBCTL_TEST_FAILED);

            if (sigprocmask(SIG_UNBLOCK, &set, NULL) < 0)
                exit(JOBCTL_BAD_SETUP);
            /* If we got here, we don't have a signal pending. Yay */
            /* Not we test for the SIGTTOU */
            write(pair.pts_fd, "a", 1);
            sleep(1);
            exit(JOBCTL_TEST_FAILED);
        }
        else
        {
            int wstatus;
            if (waitpid(pid, &wstatus, WSTOPPED) < 0)
                err(JOBCTL_BAD_SETUP, "waitpid");
            kill(pid, SIGKILL);
            exit(!(WIFSTOPPED(wstatus) && WSTOPSIG(wstatus) == SIGTTOU));
        }
    }
    else
    {
        int wstatus;
        if (waitpid(pid, &wstatus, WSTOPPED) < 0)
            err(JOBCTL_BAD_SETUP, "waitpid");
        EXPECT_TRUE(WIFEXITED(wstatus));
        EXPECT_EQ(WEXITSTATUS(wstatus), 0);
    }
}

TEST(jobctrl, orphaned_no_sig)
{
    /* Orphaned pgrps do not get terminal signals, but rather -EIO */
    pid_t pid = fork();
    ASSERT_NE(pid, -1);

    if (pid == 0)
    {
        /* Get a new session, open a pty pair */
        if (setsid() < 0)
            err(JOBCTL_BAD_SETUP, "setsid");
        pty_pair pair;
        pair.reopen_pty_with_ctty();
        raise(SIGTSTP);
        exit(0);
    }
    else
    {
        int wstatus;
        if (waitpid(pid, &wstatus, WSTOPPED) < 0)
            err(JOBCTL_BAD_SETUP, "waitpid");
        EXPECT_TRUE(WIFEXITED(wstatus));
        EXPECT_EQ(WEXITSTATUS(wstatus), 0);
    }
}

TEST(jobctrl, read_sigttin)
{
    pid_t pid = fork();
    ASSERT_NE(pid, -1);

    if (pid == 0)
    {
        /* Get a new session, open a pty pair */
        if (setsid() < 0)
            err(JOBCTL_BAD_SETUP, "setsid");
        pty_pair pair;
        pair.reopen_pty_with_ctty();
        /* Fork again... */
        pid = fork();
        if (pid < 0)
            err(JOBCTL_BAD_SETUP, "fork");
        if (pid == 0)
        {
            char c;

            if (setpgrp() < 0)
                err(JOBCTL_BAD_SETUP, "setpgrp");

            signal(SIGTTIN, SIG_IGN);
            /* With TTIN ignored, we should get EIO */
            if (read(pair.pts_fd, &c, 1) >= 0 || errno != EIO)
                exit(JOBCTL_TEST_FAILED);
            signal(SIGTTIN, SIG_DFL);
            /* And now with TTIN blocked */
            sigset_t set;
            sigemptyset(&set);
            sigaddset(&set, SIGTTOU);
            if (sigprocmask(SIG_BLOCK, &set, NULL) < 0)
                exit(JOBCTL_BAD_SETUP);

            if (read(pair.pts_fd, &c, 1) >= 0 || errno != EIO)
                exit(JOBCTL_TEST_FAILED);

            if (sigprocmask(SIG_UNBLOCK, &set, NULL) < 0)
                exit(JOBCTL_BAD_SETUP);
            /* read will raise SIGTTIN */
            read(pair.pts_fd, &c, 1);
            sleep(1);
            exit(JOBCTL_TEST_FAILED);
        }
        else
        {
            int wstatus;
            if (waitpid(pid, &wstatus, WSTOPPED) < 0)
                err(JOBCTL_BAD_SETUP, "waitpid");
            kill(pid, SIGKILL);
            exit(!(WIFSTOPPED(wstatus) && WSTOPSIG(wstatus) == SIGTTIN));
        }
    }
    else
    {
        int wstatus;
        if (waitpid(pid, &wstatus, WSTOPPED) < 0)
            err(JOBCTL_BAD_SETUP, "waitpid");
        EXPECT_TRUE(WIFEXITED(wstatus));
        EXPECT_EQ(WEXITSTATUS(wstatus), 0);
    }
}
