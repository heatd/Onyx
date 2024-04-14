// SPDX-License-Identifier: GPL-2.0-only
#include "pty.h"

#include <err.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <unistd.h>

#include <stdexcept>
#include <string>

#include <gtest/gtest.h>

TEST(pty, master_pty_open_works)
{
    int fd = posix_openpt(O_RDWR | O_NOCTTY);
    ASSERT_NE(fd, -1);
    close(fd);
}

TEST(pty, slave_pty_open_works)
{
    int fd = posix_openpt(O_RDWR | O_NOCTTY);
    ASSERT_NE(fd, -1);
    char *slave_name = ptsname(fd);
    ASSERT_NE(slave_name, nullptr);

    ASSERT_NE(unlockpt(fd), -1);

    int slave_fd = open(slave_name, O_RDWR | O_NOCTTY);
    ASSERT_NE(slave_fd, -1);
    close(slave_fd);
    close(fd);
}

TEST(pty, locked_pts_fails)
{
    /* Note: POSIX (XSI) reserves EAGAIN for this, linux does EIO */
    int fd = posix_openpt(O_RDWR | O_NOCTTY);
    ASSERT_NE(fd, -1);
    char *slave_name = ptsname(fd);
    ASSERT_NE(slave_name, nullptr);

    int slave_fd = open(slave_name, O_RDWR | O_NOCTTY);
    EXPECT_EQ(slave_fd, -1);
    close(fd);
}

TEST(pty, slave_to_master_works)
{
    std::string test = "hello world";
    char testbuf[test.length()];
    pty_pair pair;
    EXPECT_EQ(write(pair.pts_fd, test.c_str(), test.length()), test.length());
    EXPECT_EQ(read(pair.ptm_fd, testbuf, sizeof(testbuf)), sizeof(testbuf));
}

TEST(pty, master_to_slave_works)
{
    /* Note: the newline is important here, because the slave side is in canonical mode */
    std::string test = "hello world\n";
    char testbuf[test.length()];
    pty_pair pair;
    EXPECT_EQ(write(pair.ptm_fd, test.c_str(), test.length()), test.length());
    EXPECT_EQ(read(pair.pts_fd, testbuf, sizeof(testbuf)), sizeof(testbuf));
}

TEST(pty, master_signalling_works)
{
    /* Lets test if the pty slave "input" is actually being properly controlled by the master */
    pty_pair pair;
    EXPECT_EXIT(
        [&pair]() {
            if (setsid() < 0)
                err(1, "setsid");
            pair.reopen_pty_with_ctty();
            if (int st = write(pair.ptm_fd, "\x03", 1); st != 1)
                err(1, "write");
            sleep(1);
        }(),
        testing::KilledBySignal(SIGINT), ".*");
    EXPECT_EXIT(
        [&pair]() {
            if (setsid() < 0)
                err(1, "setsid");
            pair.reopen_pty_with_ctty();
        /* Note: We use PR_SET_DUMPABLE to disallow coredumps, since SIGQUIT dumps core */
#ifdef __linux__
            prctl(PR_SET_DUMPABLE, 0);
#endif
            if (int st = write(pair.ptm_fd, "\34", 1); st != 1)
                err(1, "write");
            sleep(1);
        }(),
        testing::KilledBySignal(SIGQUIT), ".*");

    /* SIGTSTP is more annoying, google test doesn't support STOP */
    pid_t pid = fork();
    ASSERT_NE(pid, -1);
    if (pid == 0)
    {
        if (setsid() < 0)
            err(1, "setsid");
        pair.reopen_pty_with_ctty();
        /* Fork again. We must avoid having an orphaned process group, because they don't get
         * terminal signals */
        pid = fork();
        if (pid < 0)
            exit(2);
        if (pid == 0)
        {
            setpgrp();
            signal(SIGTSTP, SIG_DFL);
            /* Ignore TTOU temporarily, while we set the foreground pgrp */
            signal(SIGTTOU, SIG_IGN);
            tcsetpgrp(pair.pts_fd, getpgrp());
            signal(SIGTTOU, SIG_DFL);
            /* Write ^Z */
            if (int st = write(pair.ptm_fd, "\32", 1); st != 1)
                err(1, "write");
            sleep(1);
            exit(1);
        }
        else
        {
            int status;
            if (waitpid(pid, &status, WSTOPPED) < 0)
                err(1, "waitpid");
            kill(pid, SIGKILL);
            exit(!(WIFSTOPPED(status) && WSTOPSIG(status) == SIGTSTP));
        }
    }
    else
    {
        int status;
        ASSERT_EQ(waitpid(pid, &status, 0), pid);
        EXPECT_TRUE(WIFEXITED(status));
        EXPECT_EQ(WEXITSTATUS(status), 0);
    }
}

TEST(pty, master_close_hangup)
{
    pty_pair pair;
    close(pair.ptm_fd);
    EXPECT_EQ(write(pair.pts_fd, "a", 1), -1);
    EXPECT_EQ(errno, EIO);
}
