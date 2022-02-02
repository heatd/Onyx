/*
 * Copyright (c) 2020 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 */
#include <fcntl.h>
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>

#include <chrono>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

#include <gtest/gtest.h>

#include "../include/child_process_helper.h"

using namespace std::chrono_literals;

TEST(ExitTest, MultipleThreadsExit)
{
    ChildProcessHelper h;
    bool should_exit = false;
    Waiter wa;

    auto wstatus = h.execute_process([](const ChildProcessHelper &c) {},
                                     [&](const ChildProcessHelper &c) -> int {
                                         std::vector<std::thread> v;

                                         for (unsigned int i = 0; i < 100; i++)
                                         {
                                             std::thread t{[&]() {
                                                 while (!should_exit)
                                                     sleep(1000000);
                                             }};

                                             v.push_back(std::move(t));
                                         }

                                         std::cout.flush();

                                         std::this_thread::sleep_for(800ms);
                                         should_exit = true;
                                         wa.Wake();
                                         raise(SIGSTOP);

                                         for (auto &t : v)
                                             t.join();

                                         return 188;
                                     },
                                     [&](const ChildProcessHelper &c) {
                                         wa.Wait();
                                         std::this_thread::sleep_for(800ms);
                                         kill(c.pid, SIGCONT);
                                     });

    EXPECT_TRUE(WIFEXITED(wstatus));
    EXPECT_EQ(WEXITSTATUS(wstatus), 188);
}

TEST(ExitTest, MultipleThreadsKill)
{
    ChildProcessHelper h;
    bool should_exit = false;
    Waiter wa;

    auto wstatus = h.execute_process([](const ChildProcessHelper &c) {},
                                     [&](const ChildProcessHelper &c) -> int {
                                         std::vector<std::thread> v;

                                         for (unsigned int i = 0; i < 100; i++)
                                         {
                                             std::thread t{[&]() {
                                                 while (!should_exit)
                                                     sleep(1000000);
                                             }};

                                             v.push_back(std::move(t));
                                         }
                                         std::cout.flush();

                                         std::this_thread::sleep_for(800ms);
                                         should_exit = true;
                                         wa.Wake();
                                         raise(SIGSTOP);

                                         for (auto &t : v)
                                             t.join();

                                         return 188;
                                     },
                                     [&](const ChildProcessHelper &c) {
                                         wa.Wait();
                                         std::this_thread::sleep_for(800ms);
                                         kill(c.pid, SIGKILL);
                                     });

    EXPECT_TRUE(WIFSIGNALED(wstatus));
    EXPECT_EQ(WTERMSIG(wstatus), SIGKILL);
}
