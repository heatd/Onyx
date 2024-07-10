/*
 * Copyright (c) 2022 - 2024 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/ip.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <limits>
#include <memory>

#include <gtest/gtest.h>

TEST(UnixSocket, SysSocketWorks)
{
    int fd = socket(AF_UNIX, SOCK_DGRAM, 0);
    ASSERT_NE(fd, -1);

    close(fd);

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    ASSERT_NE(fd, -1);
    close(fd);
}

TEST(UnixSocket, BindFilesystemWorks)
{
    int fd = socket(AF_UNIX, SOCK_DGRAM, 0);

    ASSERT_NE(fd, -1);

    sockaddr_un un;
    un.sun_family = AF_UNIX;
    strcpy(un.sun_path, "socket0");
    int st = bind(fd, (sockaddr *) &un, SUN_LEN(&un));

    ASSERT_EQ(st, 0);

    ASSERT_EQ(access("socket0", F_OK), 0);

    // Check if we can connect with the socket present in the fs
    int fd2 = socket(AF_UNIX, SOCK_DGRAM, 0);
    ASSERT_NE(fd2, -1);
    ASSERT_EQ(connect(fd2, (sockaddr *) &un, SUN_LEN(&un)), 0);
    close(fd2);

    unlink("socket0");

    // Now check that we can't connect after unlinking
    int fd3 = socket(AF_UNIX, SOCK_DGRAM, 0);
    ASSERT_NE(fd3, -1);
    ASSERT_EQ(connect(fd3, (sockaddr *) &un, SUN_LEN(&un)), -1);
    close(fd3);
    close(fd);
}

TEST(UnixSocket, BindFilesystemEAddrInUse)
{
    int fd = socket(AF_UNIX, SOCK_DGRAM, 0);

    ASSERT_NE(fd, -1);

    sockaddr_un un;
    un.sun_family = AF_UNIX;
    strcpy(un.sun_path, "socket0");
    int st = bind(fd, (sockaddr *) &un, SUN_LEN(&un));

    ASSERT_EQ(st, 0);

    ASSERT_EQ(access("socket0", F_OK), 0);

    int fd2 = socket(AF_UNIX, SOCK_DGRAM, 0);
    st = bind(fd2, (sockaddr *) &un, SUN_LEN(&un));
    int err = errno;
    ASSERT_EQ(st, -1);
    ASSERT_EQ(err, EADDRINUSE);

    close(fd);
    close(fd2);
    unlink("socket0");
}

TEST(UnixSocket, BindAnonWorks)
{
    int fd = socket(AF_UNIX, SOCK_DGRAM, 0);

    ASSERT_NE(fd, -1);

    sockaddr_un un;
    un.sun_family = AF_UNIX;
    un.sun_path[0] = '\0';
    strcpy(un.sun_path + 1, "socket0");
    size_t un_len = strlen("socket0") + sizeof(sa_family_t);

    int st = bind(fd, (sockaddr *) &un, un_len);

    ASSERT_EQ(st, 0);

    // Check if we can connect with the socket bound
    int fd2 = socket(AF_UNIX, SOCK_DGRAM, 0);
    ASSERT_NE(fd2, -1);
    ASSERT_EQ(connect(fd2, (sockaddr *) &un, un_len), 0);
    close(fd2);
    close(fd);

    // Check if we can connect with the server socket unbound
    fd2 = socket(AF_UNIX, SOCK_DGRAM, 0);
    ASSERT_NE(fd2, -1);
    ASSERT_EQ(connect(fd2, (sockaddr *) &un, un_len), -1);
    ASSERT_EQ(errno, ECONNREFUSED);
}

TEST(UnixSocket, BindAnonEAddrInUse)
{
    int fd = socket(AF_UNIX, SOCK_DGRAM, 0);

    ASSERT_NE(fd, -1);

    sockaddr_un un;
    un.sun_family = AF_UNIX;
    un.sun_path[0] = '\0';
    strcpy(un.sun_path + 1, "socket0");
    size_t un_len = strlen("socket0") + sizeof(sa_family_t);
    int st = bind(fd, (sockaddr *) &un, un_len);

    ASSERT_EQ(st, 0);

    int fd2 = socket(AF_UNIX, SOCK_DGRAM, 0);
    st = bind(fd2, (sockaddr *) &un, un_len);
    int err = errno;
    ASSERT_EQ(st, -1);
    ASSERT_EQ(err, EADDRINUSE);

    close(fd);
    close(fd2);
}

TEST(UnixSocket, FdPassingWorks)
{
    int fds[2];
    ASSERT_NE(socketpair(AF_UNIX, SOCK_DGRAM, 0, fds), -1);

    int devnull = open("/dev/null", O_RDWR);
    int devzero = open("/dev/zero", O_RDWR);
    ASSERT_NE(devnull, -1);
    ASSERT_NE(devzero, -1);

    char buffer[CMSG_SPACE(sizeof(int) * 2)];
    struct cmsghdr *cmsg = (struct cmsghdr *) buffer;
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(int) * 2);
    int *data = (int *) CMSG_DATA(cmsg);
    data[0] = devnull;
    data[1] = devzero;

    struct msghdr msg;
    msg.msg_control = cmsg;
    msg.msg_controllen = cmsg->cmsg_len;
    msg.msg_flags = 0;

    struct iovec v;
    v.iov_base = fds;
    v.iov_len = 1;
    msg.msg_iov = &v;
    msg.msg_iovlen = 1;
    msg.msg_name = NULL;
    msg.msg_namelen = 0;

    ASSERT_EQ(sendmsg(fds[0], &msg, 0), 1);
    ASSERT_EQ(recvmsg(fds[1], &msg, 0), 1);

    EXPECT_FALSE(msg.msg_flags & MSG_CTRUNC);
    bool found_scm_rights = false;

    int devnull2, devzero2;

    for (cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg))
    {
        if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS)
        {
            found_scm_rights = true;
            int *data = (int *) CMSG_DATA(cmsg);
            devnull2 = data[0];
            devzero2 = data[1];
        }
    }

    ASSERT_TRUE(found_scm_rights);
    close(devnull2);
    close(devzero2);
    close(devnull);
    close(devzero);
    close(fds[0]);
    close(fds[1]);
}
