
/*
 * Copyright (c) 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
#define _POSIX_C_SOURCE
#include "include/process.h"

#include <err.h>
#include <signal.h>
#include <spawn.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cassert>
#include <filesystem>
#include <string>
#include <vector>

#include "include/test.h"

/**
 * @brief Run a process and return its pid
 *
 * @param exec_path_ Path to the executable
 * @param argv Vector of arguments (NOT NULL TERMINATED)
 * @param envp envp (NULL-terminated)
 * @return -1 on error, pids > 0
 */
pid_t run_process(const std::filesystem::path &exec_path_, const std::vector<std::string> &argv,
                  char **envp)
{

    // Set up a raw argv array (with a terminating NULL) from the good, safe argv we were given
    const char **actual_argv = (const char **) malloc(sizeof(char *) * (argv.size() + 1));

    if (!actual_argv)
        return -1;

    for (size_t i = 0; i < argv.size(); i++)
    {
        actual_argv[i] = argv[i].c_str();
    }

    actual_argv[argv.size()] = nullptr;

    pid_t pid;

    int err =
        posix_spawn(&pid, exec_path_.c_str(), nullptr, nullptr, (char *const *) actual_argv, envp);

    free(actual_argv);

    if (err)
    {
        errno = err;
        return -1;
    }

    return pid;
}

/**
 * @brief Interpret a wait status into a test result
 *
 * @param wstatus Wait status
 * @param test_name Name of the test (for logging purposes)
 * @return A valid test_result value
 */
test_result interpret_wstatus(int wstatus, const std::string &test_name)
{
    if (WIFEXITED(wstatus))
    {
        const int exit = WEXITSTATUS(wstatus);
        // Let's assume all good exit codes are 0.
        if (exit != 0)
        {
            fprintf(stderr, "%s: exited with exit status %d\n", test_name.c_str(), exit);
            return test_result::error;
        }

        return test_result::ok;
    }
    else if (WIFSIGNALED(wstatus))
    {
        const int sig = WTERMSIG(wstatus);

        fprintf(stderr, "%s: exited with signal %s (%d)\n", test_name.c_str(), strsignal(sig), sig);

        return test_result::error;
    }

    assert(0);
}

/**
 * @brief Wait for a process
 * Note: May SIGTERM and SIGKILL a process if it times out.
 *
 * @param pid PID to wait for
 * @param test_name Name of the test (for logging purposes)
 * @param timeout Timeout in seconds, if set for the test, else -1 (sleeps forever)
 * @return A valid test_result value
 */
test_result wait_for_process(pid_t pid, const std::string &test_name, int timeout)
{
    int wstatus;

    while (true)
    {
        pid_t st = waitpid(pid, &wstatus, WNOHANG);

        if (st < 0 && errno != EINTR)
            err(1, "waitpid");
        else if (st == pid)
        {
            // Found, great!
            break;
        }

        if (!timeout)
        {
            fprintf(stderr, "test-runner: %s timed out, killing...\n", test_name.c_str());
            // Timeout, kill the other process and return failure
            kill(pid, SIGTERM);
            sleep(3); // Wait for a bit more before SIGKILL
            kill(pid, SIGKILL);

            // Best attempt at reaping the wstatus
            // The process could plausibly be stuck in an uninterruptible sleep
            // so, if we couldn't kill it, just assume error.
            // waitpid calls check if they actually got the right pid, so this
            // should not be a problem.
            if (waitpid(pid, &wstatus, WNOHANG) == pid)
                break;

            return test_result::error;
        }

        timeout = sleep(timeout);
    }

    return interpret_wstatus(wstatus, test_name);
}

/**
 * @brief Set up SIGCHLD handling
 *
 */
void setup_sigchld()
{
    // This is a dummy function for SIGCHLD
    // wait should be interrupted, and we should then catch the EINTR in sleep, loop back and poll
    // waitpid, see we have a waiting child, and get out.
    struct sigaction sa;
    sa.sa_flags = 0; // No SA_RESTART.
    sigemptyset(&sa.sa_mask);
    sa.sa_handler = [](int) {};
    if (sigaction(SIGCHLD, &sa, nullptr) < 0)
        err(1, "sigaction");
}
