/*
 * Copyright (c) 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#include <arpa/inet.h>
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
