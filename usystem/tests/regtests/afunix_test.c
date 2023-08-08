// SPDX-License-Identifier: GPL-2.0-only
#include <assert.h>
#include <err.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

static sig_atomic_t got_sigpipe = 0;
static int failed = 0;

#define ASSERT_EQ(expected, actual)                                                       \
    ({                                                                                    \
        if ((expected) != (actual))                                                       \
        {                                                                                 \
            fprintf(stderr, "Test failed: %s: " #expected " != " #actual "\n", __func__); \
            failed = 1;                                                                   \
            return;                                                                       \
        }                                                                                 \
    })

static void sigpipe(int sig)
{
    (void) sig;
    got_sigpipe = 1;
}

static void reset_global(void)
{
    got_sigpipe = 0;
}

static void xsocketpair(int domain, int type, int protocol, int sockfd[2])
{
    if (socketpair(domain, type, protocol, sockfd) < 0)
        err(1, "socketpair");
}

static void xshutdown(int fd, int how)
{
    if (shutdown(fd, how) < 0)
        err(1, "shutdown");
}

static char c = 'a';

static void test_shutdown_rd_other(void)
{
    // Test how shutdown read affects the other end
    int sockfd[2], st;
    struct sockaddr_un addr;
    socklen_t len = sizeof(addr);

    xsocketpair(AF_UNIX, SOCK_STREAM, 0, sockfd);

    xshutdown(sockfd[0], SHUT_RD);
    st = write(sockfd[1], &c, 1);

    ASSERT_EQ(-1, st);
    ASSERT_EQ(EPIPE, errno);
    ASSERT_EQ(1, got_sigpipe);
    // Linux says: EPIPE + SIGPIPE
    //
    // Check if getpeername is still valid (aka if we MUST keep peer attached)
    st = getpeername(sockfd[1], (struct sockaddr *) &addr, &len);
    ASSERT_EQ(0, st);
    // Linux says: yes. The peer is still referred to in the non-shutdown socket.
    // The shutdown socket has the well defined behavior (by POSIX) of EINVAL.
    // This happens for both shutdown SHUT_RDWR and SHUT_RD (i.e we cannot use the
    // shutdown as an opportunity to unref ourselves on the peer).
}

static void test_shutdown_wr_self(void)
{
    int sockfd[2], st;
    xsocketpair(AF_UNIX, SOCK_STREAM, 0, sockfd);

    // Shudown on self (WR)
    xshutdown(sockfd[0], SHUT_WR);
    st = write(sockfd[0], &c, 1);
    ASSERT_EQ(-1, st);
    ASSERT_EQ(EPIPE, errno);
    ASSERT_EQ(1, got_sigpipe);
    // Linux says: EPIPE + SIGPIPE
}

static void test_shutdown_wr_other(void)
{
    int sockfd[2], st;
    xsocketpair(AF_UNIX, SOCK_STREAM, 0, sockfd);

    // Shutdown on other (WR)
    xshutdown(sockfd[0], SHUT_WR);
    st = read(sockfd[1], &c, 1);
    ASSERT_EQ(0, st);
    // Linux says: EOF
}

static void test_shutdown_rd_self(void)
{
    int sockfd[2], st;
    xsocketpair(AF_UNIX, SOCK_STREAM, 0, sockfd);

    // Shutdown test on self (RD)
    xshutdown(sockfd[1], SHUT_RD);
    st = read(sockfd[1], &c, 1);
    ASSERT_EQ(0, st);
    // Linux says: EOF
}

int main(int argc, char **argv)
{
    signal(SIGPIPE, sigpipe);
    test_shutdown_rd_other();
    reset_global();
    test_shutdown_wr_other();
    reset_global();
    test_shutdown_wr_self();
    reset_global();
    test_shutdown_rd_self();
    return failed;
}
