/*
 * Copyright (c) 2020 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 */

#ifndef WAITER_H
#define WAITER_H

#include <fcntl.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cstring>
#include <string>

#include <gtest/gtest.h>

class Waiter
{
private:
    int fds[2];

public:
    Waiter()
    {
        if (pipe(fds) < 0)
        {
            throw std::runtime_error("pipe() failed");
        }
    }

    ~Waiter()
    {
        close(fds[0]);
        close(fds[1]);
    }

    void Wait() const
    {
        char c;
        ssize_t st;

        while ((st = read(fds[0], &c, 1)) == -1 && errno == EINTR)
        {
        }

        if (st == -1)
        {
            throw std::runtime_error(std::string("read error: ") + std::strerror(errno));
        }

        ASSERT_EQ(st, 1);
    }

    void Wake() const
    {
        char c = 'A';
        ASSERT_EQ(write(fds[1], &c, 1), 1);
    }

    void Write(const char *buf, ssize_t len) const
    {
        ASSERT_EQ(write(fds[1], buf, len), len);
    }

    void RemapToStdin() const
    {
        dup2(fds[0], STDIN_FILENO);
    }

    void RemapToStdout() const
    {
        dup2(fds[1], STDOUT_FILENO);
    }

    void CloseReadEnd() const
    {
        close(fds[0]);
    }

    void CloseWriteEnd() const
    {
        close(fds[1]);
    }

    void Close() const
    {
        CloseReadEnd();
        CloseWriteEnd();
    }
};

#endif
