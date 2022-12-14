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

#include <future>
#include <latch>
#include <limits>
#include <memory>
#include <string>
#include <thread>

#include <gtest/gtest.h>

using namespace std::string_view_literals;

std::string_view lorem_ipsum =
    "Sed ut perspiciatis unde omnis iste natus error sit voluptatem accusantium doloremque "
    "laudantium, totam rem aperiam, eaque ipsa quae ab illo inventore veritatis et quasi "
    "architecto beatae vitae dicta sunt explicabo. Nemo enim ipsam voluptatem quia voluptas sit "
    "aspernatur aut odit aut fugit, sed quia consequuntur magni dolores eos qui ratione voluptatem "
    "sequi nesciunt. Neque porro quisquam est, qui dolorem ipsum quia dolor sit amet, consectetur, "
    "adipisci velit, sed quia non numquam eius modi tempora incidunt ut labore et dolore magnam "
    "aliquam quaerat voluptatem. Ut enim ad minima veniam, quis nostrum exercitationem ullam "
    "corporis suscipit laboriosam, nisi ut aliquid ex ea commodi consequatur? Quis autem vel eum "
    "iure reprehenderit qui in ea voluptate velit esse quam nihil molestiae consequatur, vel illum "
    "qui dolorem eum fugiat quo voluptas nulla pariatur?"sv;

struct sync_data
{
    std::promise<int> out;
};

void accept_connections(int sock, sync_data &sdata)
{
    std::string str;
    int connfd = accept(sock, nullptr, nullptr);

    if (connfd < 0)
    {
        sdata.out.set_value(-errno);
        return;
    }

    char buf[200];

    ssize_t status;
    while ((status = recv(connfd, buf, 200, 0)) > 0)
    {
        str.append(buf, status);
    }

    if (status < 0)
    {
        sdata.out.set_value(-errno);
        return;
    }

    shutdown(connfd, SHUT_RDWR);
    close(connfd);

    sdata.out.set_value(!(str == lorem_ipsum));
}

TEST(Tcp, Inet4AnyConnection)
{
    sync_data sdata{};
    int sock = socket(AF_INET, SOCK_STREAM, 0);

    ASSERT_NE(sock, -1);

    sockaddr_in sa = {};
    sa.sin_addr.s_addr = INADDR_ANY;
    sa.sin_port = htons(1066);
    sa.sin_family = AF_INET;

    ASSERT_NE(bind(sock, (const sockaddr *) &sa, sizeof(sa)), -1);

    ASSERT_NE(listen(sock, 0), -1);

    int sock2 = socket(AF_INET, SOCK_STREAM, 0);

    ASSERT_NE(sock2, -1);

    std::thread t([&]() { accept_connections(sock, sdata); });

    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    ASSERT_NE(connect(sock2, (const sockaddr *) &sa, sizeof(sa)), -1);

    for (size_t i = 0; i < lorem_ipsum.size(); i += 20)
    {
        size_t to_transfer = std::min<size_t>(lorem_ipsum.size() - i, 20);
        EXPECT_NE(send(sock2, &lorem_ipsum[i], to_transfer, 0), -1);
    }

    ASSERT_NE(shutdown(sock2, SHUT_RDWR), -1);

    t.join();

    close(sock2);

    close(sock);

    auto future = sdata.out.get_future();
    future.wait();
    ASSERT_EQ(future.get(), 0);
}

TEST(Tcp, Inet6AnyConnection)
{
    sync_data sdata{};
    int sock = socket(AF_INET6, SOCK_STREAM, 0);

    ASSERT_NE(sock, -1);

    sockaddr_in6 sa = {};
    sa.sin6_addr = IN6ADDR_ANY_INIT;
    sa.sin6_port = htons(1066);
    sa.sin6_family = AF_INET6;
    sa.sin6_flowinfo = 0;
    sa.sin6_scope_id = 0;

    ASSERT_NE(bind(sock, (const sockaddr *) &sa, sizeof(sa)), -1);

    ASSERT_NE(listen(sock, 0), -1);

    int sock2 = socket(AF_INET6, SOCK_STREAM, 0);

    ASSERT_NE(sock2, -1);

    std::thread t([&]() { accept_connections(sock, sdata); });

    sa.sin6_addr = IN6ADDR_LOOPBACK_INIT;
    ASSERT_NE(connect(sock2, (const sockaddr *) &sa, sizeof(sa)), -1);

    for (size_t i = 0; i < lorem_ipsum.size(); i += 20)
    {
        size_t to_transfer = std::min<size_t>(lorem_ipsum.size() - i, 20);
        EXPECT_NE(send(sock2, &lorem_ipsum[i], to_transfer, 0), -1);
    }

    ASSERT_NE(shutdown(sock2, SHUT_RDWR), -1);

    t.join();

    close(sock2);

    close(sock);

    auto future = sdata.out.get_future();
    future.wait();
    ASSERT_EQ(future.get(), 0);
}

TEST(Tcp, DISABLED_Inet6Inet4Connection)
{
    sync_data sdata{};
    int sock = socket(AF_INET6, SOCK_STREAM, 0);

    ASSERT_NE(sock, -1);

    sockaddr_in6 sa = {};
    sa.sin6_addr = IN6ADDR_ANY_INIT;
    sa.sin6_port = htons(1066);
    sa.sin6_family = AF_INET6;
    sa.sin6_flowinfo = 0;
    sa.sin6_scope_id = 0;

    ASSERT_NE(bind(sock, (const sockaddr *) &sa, sizeof(sa)), -1);

    ASSERT_NE(listen(sock, 0), -1);

    int sock2 = socket(AF_INET, SOCK_STREAM, 0);

    ASSERT_NE(sock2, -1);

    sockaddr_in sa2;
    sa2.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sa2.sin_family = AF_INET;
    sa2.sin_port = htons(1066);
    memset(sa2.sin_zero, 0, sizeof(sa2.sin_zero));

    std::thread t([&]() { accept_connections(sock, sdata); });

    sa.sin6_addr = IN6ADDR_LOOPBACK_INIT;
    ASSERT_NE(connect(sock2, (const sockaddr *) &sa2, sizeof(sa2)), -1);

    for (size_t i = 0; i < lorem_ipsum.size(); i += 20)
    {
        size_t to_transfer = std::min<size_t>(lorem_ipsum.size() - i, 20);
        EXPECT_NE(send(sock2, &lorem_ipsum[i], to_transfer, 0), -1);
    }

    ASSERT_NE(shutdown(sock2, SHUT_RDWR), -1);

    t.join();

    close(sock2);

    close(sock);

    auto future = sdata.out.get_future();
    future.wait();
    ASSERT_EQ(future.get(), 0);
}
