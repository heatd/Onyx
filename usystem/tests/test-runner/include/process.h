/*
 * Copyright (c) 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
#pragma once

#include <err.h>
#include <unistd.h>

#include <cassert>
#include <filesystem>
#include <string>
#include <vector>

#include "test.h"

/**
 * @brief Run a process and return its pid
 *
 * @param exec_path_ Path to the executable
 * @param argv Vector of arguments (NOT NULL TERMINATED)
 * @param envp envp (NULL-terminated)
 * @return -1 on error, pids > 0
 */
pid_t run_process(const std::filesystem::path &exec_path_, const std::vector<std::string> &argv,
                  char **envp);

/**
 * @brief Interpret a wait status into a test result
 *
 * @param wstatus Wait status
 * @param test_name Name of the test (for logging purposes)
 * @return A valid test_result value
 */
test_result interpret_wstatus(int wstatus, const std::string &test_name);

/**
 * @brief Wait for a process
 * Note: May SIGTERM and SIGKILL a process if it times out.
 *
 * @param pid PID to wait for
 * @param test_name Name of the test (for logging purposes)
 * @param timeout Timeout in seconds, if set for the test, else -1 (sleeps forever)
 * @return A valid test_result value
 */
test_result wait_for_process(pid_t pid, const std::string &test_name, int timeout);

/**
 * @brief Set up SIGCHLD handling
 *
 */
void setup_sigchld();
