/*
 * Copyright (c) 2020 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 */

#ifndef CHILD_PROCESS_HELPER_H
#define CHILD_PROCESS_HELPER_H

#include <unistd.h>

#include <functional>
#include <stdexcept>
#include <string>

#include <gtest/gtest.h>

#include "waiter.h"

/* Forks and executes some code in the parent and some code in the child */
struct ChildProcessHelper
{
    Waiter w;
    pid_t pid;

    int execute_process(std::function<void(const ChildProcessHelper&)> parent_code,
                        std::function<int(const ChildProcessHelper&)> child_code,
                        std::function<void(const ChildProcessHelper&)> post_wake_code =
                            std::function<void(const ChildProcessHelper&)>{
                                [](const ChildProcessHelper&) {}})
    {
        pid = fork();

        if (pid < 0)
        {
            throw std::runtime_error(std::string("fork error") + strerror(errno));
        }

        if (pid == 0)
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

            if (wait(&wstatus) < 0)
                throw std::runtime_error("wait error");

            return wstatus;
        }
    }

    int operator()(std::function<void(const ChildProcessHelper&)> parent_code,
                   std::function<int(const ChildProcessHelper&)> child_code,
                   std::function<void(const ChildProcessHelper&)> post_wake_code =
                       std::function<void(const ChildProcessHelper&)>{
                           [](const ChildProcessHelper&) {}})
    {
        auto status = execute_process(parent_code, child_code, post_wake_code);

        if (!WIFEXITED(status))
        {
            throw std::runtime_error(std::string("wait: Child did not exit normally, exit code: ") +
                                     std::to_string(status));
        }

        return WEXITSTATUS(status);
    }
};

#endif
